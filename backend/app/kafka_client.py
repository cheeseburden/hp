"""
kafka_client.py — Real Apache Kafka producer/consumer using confluent-kafka.
Handles event streaming through the pipeline.
"""

import json
import logging
import threading
import asyncio
from typing import Optional, Callable, Dict, Any
from confluent_kafka import Producer, Consumer, KafkaError, KafkaException
from confluent_kafka.admin import AdminClient, NewTopic
from app.config import KAFKA_BOOTSTRAP_SERVERS, KAFKA_RAW_EVENTS_TOPIC, KAFKA_ALERTS_TOPIC, KAFKA_AUDIT_TOPIC

logger = logging.getLogger("hpe.kafka")

_producer: Optional[Producer] = None
_consumer: Optional[Consumer] = None
_admin: Optional[AdminClient] = None
_connected = False
_consumer_thread: Optional[threading.Thread] = None
_consumer_running = False
_result_queue: Optional[asyncio.Queue] = None



def connect_kafka() -> bool:
    """Initialize Kafka producer, consumer, and create topics."""
    global _producer, _consumer, _admin, _connected

    try:
        conf = {"bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS}

        # Admin client — create topics
        _admin = AdminClient(conf)
        topics = [
            NewTopic(KAFKA_RAW_EVENTS_TOPIC, num_partitions=3, replication_factor=3),
            NewTopic(KAFKA_ALERTS_TOPIC, num_partitions=1, replication_factor=3),
            NewTopic(KAFKA_AUDIT_TOPIC, num_partitions=1, replication_factor=3),
        ]
        futures = _admin.create_topics(topics)
        for topic, future in futures.items():
            try:
                future.result()
                logger.info(f"Created Kafka topic: {topic}")
            except KafkaException as e:
                if "TOPIC_ALREADY_EXISTS" in str(e):
                    logger.info(f"Kafka topic already exists: {topic}")
                else:
                    logger.warning(f"Topic creation warning for {topic}: {e}")

        # Producer
        _producer = Producer({
            "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
            "client.id": "hpe-pipeline-producer",
            "acks": "all",
        })

        # Consumer
        _consumer = Consumer({
            "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
            "group.id": "hpe-pipeline-consumer",
            "auto.offset.reset": "latest",
        })

        _connected = True
        logger.info(f"Kafka connected at {KAFKA_BOOTSTRAP_SERVERS}")
        return True

    except Exception as e:
        logger.error(f"Kafka connection failed: {e}")
        _connected = False
        return False


def is_connected() -> bool:
    """Check if Kafka is connected."""
    return _connected


def produce_event(topic: str, event: Dict[str, Any], key: Optional[str] = None) -> bool:
    """Produce a single event to a Kafka topic."""
    if not _producer:
        logger.warning("Kafka producer not initialized, skipping produce")
        return False

    try:
        value = json.dumps(event, default=str).encode("utf-8")
        _producer.produce(
            topic=topic,
            value=value,
            key=key.encode("utf-8") if key else None,
            callback=_delivery_callback,
        )
        _producer.poll(0)  # Trigger delivery callbacks
        return True
    except Exception as e:
        logger.error(f"Kafka produce error: {e}")
        return False


def flush():
    """Flush all pending Kafka messages."""
    if _producer:
        _producer.flush(timeout=5)


def produce_raw_event(event: Dict[str, Any]) -> bool:
    """Publish a raw network event to the raw-events topic."""
    return produce_event(KAFKA_RAW_EVENTS_TOPIC, event, key=event.get("user", "unknown"))


def produce_alert(alert: Dict[str, Any]) -> bool:
    """Publish a threat alert to the alerts topic."""
    return produce_event(KAFKA_ALERTS_TOPIC, alert, key=alert.get("event_id", "unknown"))


def produce_audit(audit_entry: Dict[str, Any]) -> bool:
    """Publish an audit log entry to the audit topic."""
    return produce_event(KAFKA_AUDIT_TOPIC, audit_entry)


def _delivery_callback(err, msg):
    """Callback for Kafka message delivery."""
    if err:
        logger.error(f"Kafka delivery failed: {err}")
    else:
        logger.debug(f"Kafka delivered to {msg.topic()} [{msg.partition()}] @ {msg.offset()}")


def get_topic_stats() -> Dict[str, Any]:
    """Get real Kafka topic metadata, partition offsets, and consumer group info.
    
    Uses a fresh AdminClient and a temporary Consumer to avoid conflicts
    with the background consumer thread that holds the shared _consumer.
    """
    if not _connected:
        return {"error": "Kafka not connected"}

    try:
        # Create a fresh admin client for metadata queries
        admin = AdminClient({"bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS})
        metadata = admin.list_topics(timeout=10)
        topics_info = {}

        for topic_name, topic_meta in metadata.topics.items():
            if topic_name.startswith("_"):  # Skip internal topics
                continue
            partitions = []
            for p_id, p_meta in topic_meta.partitions.items():
                partitions.append({
                    "id": p_id,
                    "leader": p_meta.leader,
                    "replicas": list(p_meta.replicas),
                    "isrs": list(p_meta.isrs),
                })
            topics_info[topic_name] = {
                "partitions": partitions,
                "partition_count": len(partitions),
            }

        # Use a temporary consumer for offset queries (the main _consumer is
        # actively subscribed in the background thread and cannot be shared)
        from confluent_kafka import TopicPartition
        stats_consumer = Consumer({
            "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
            "group.id": "hpe-pipeline-consumer",
            "auto.offset.reset": "latest",
            "enable.auto.commit": False,  # read-only — don't commit
        })

        # Get consumer group offsets
        consumer_lag = {}
        try:
            for topic_name in [KAFKA_RAW_EVENTS_TOPIC, KAFKA_ALERTS_TOPIC]:
                if topic_name in topics_info:
                    tp_list = [
                        TopicPartition(topic_name, p["id"])
                        for p in topics_info[topic_name]["partitions"]
                    ]
                    committed = stats_consumer.committed(tp_list, timeout=5)
                    for tp in committed:
                        if tp.offset >= 0:
                            lo, hi = stats_consumer.get_watermark_offsets(tp, timeout=5)
                            lag = hi - tp.offset if hi >= 0 and tp.offset >= 0 else 0
                            key = f"{tp.topic}[{tp.partition}]"
                            consumer_lag[key] = {
                                "topic": tp.topic,
                                "partition": tp.partition,
                                "committed_offset": tp.offset,
                                "latest_offset": hi,
                                "lag": lag,
                            }
        except Exception as e:
            logger.warning(f"Could not fetch consumer offsets: {e}")

        # Count total messages produced (from watermarks)
        total_messages = 0
        for topic_name in [KAFKA_RAW_EVENTS_TOPIC, KAFKA_ALERTS_TOPIC, KAFKA_AUDIT_TOPIC]:
            if topic_name in topics_info:
                for p_info in topics_info[topic_name]["partitions"]:
                    try:
                        lo, hi = stats_consumer.get_watermark_offsets(
                            TopicPartition(topic_name, p_info["id"]), timeout=5
                        )
                        total_messages += (hi - lo) if hi >= 0 and lo >= 0 else 0
                    except Exception:
                        pass

        # Clean up the temporary consumer
        stats_consumer.close()

        return {
            "connected": True,
            "broker_count": len(metadata.brokers),
            "topics": topics_info,
            "consumer_group": "hpe-pipeline-consumer",
            "consumer_lag": consumer_lag,
            "total_messages_in_topics": total_messages,
        }

    except Exception as e:
        logger.error(f"Failed to get Kafka stats: {e}")
        return {"error": str(e), "connected": _connected}


def disconnect_kafka():
    """Clean shutdown of Kafka connections."""
    global _producer, _consumer, _connected
    stop_consumer()
    if _producer:
        _producer.flush(timeout=5)
    if _consumer:
        _consumer.close()
    _connected = False
    logger.info("Kafka disconnected")


def start_consumer(process_callback: Callable, loop: asyncio.AbstractEventLoop, 
                   result_queue: asyncio.Queue):
    """Start a background thread that consumes from hpe-raw-events."""
    global _consumer_thread, _consumer_running, _result_queue
    _result_queue = result_queue
    _consumer_running = True
    
    _consumer_thread = threading.Thread(
        target=_consumer_loop, 
        args=(process_callback, loop, result_queue),
        daemon=True
    )
    _consumer_thread.start()
    logger.info("Kafka consumer thread started")


def _consumer_loop(process_callback, loop, result_queue):
    """Blocking consumer loop — runs in a separate thread."""
    global _consumer_running
    
    if not _consumer:
        logger.error("Consumer not initialized")
        return
    
    _consumer.subscribe([KAFKA_RAW_EVENTS_TOPIC])
    logger.info(f"Subscribed to {KAFKA_RAW_EVENTS_TOPIC}")
    
    while _consumer_running:
        try:
            msg = _consumer.poll(timeout=1.0)  # Block for 1 second max
            if msg is None:
                continue
            if msg.error():
                logger.error(f"Consumer error: {msg.error()}")
                continue
            
            # Deserialize the event
            raw = json.loads(msg.value().decode("utf-8"))
            logger.info(f"Consumed event from partition {msg.partition()} offset {msg.offset()}")
            
            # Process through the pipeline (ML + Vault + ES)
            result = process_callback(raw)
            
            # Push result to async queue (thread-safe bridge)
            asyncio.run_coroutine_threadsafe(
                result_queue.put(result),
                loop
            )
            
        except Exception as e:
            logger.error(f"Consumer loop error: {e}")
    
    logger.info("Consumer loop stopped")


def stop_consumer():
    """Stop the background consumer."""
    global _consumer_running
    _consumer_running = False
    if _consumer_thread:
        _consumer_thread.join(timeout=5)
    logger.info("Kafka consumer stopped")

