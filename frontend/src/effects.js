/**
 * effects.js — Star field particle background effect.
 */

let canvas = null;
let ctx = null;
let stars = [];
let animFrame = null;

const STAR_COUNT = 200;

/**
 * Initialize the star field background
 */
export function initStarField(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  canvas = document.createElement('canvas');
  canvas.style.cssText = `
    position: absolute;
    top: 0; left: 0;
    width: 100%; height: 100%;
    z-index: 0;
    pointer-events: none;
  `;
  container.appendChild(canvas);
  ctx = canvas.getContext('2d');

  resize();
  createStars();
  animate();

  window.addEventListener('resize', resize);
}

function resize() {
  if (!canvas) return;
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
}

function createStars() {
  stars = [];
  for (let i = 0; i < STAR_COUNT; i++) {
    stars.push({
      x: Math.random() * window.innerWidth,
      y: Math.random() * window.innerHeight,
      radius: Math.random() * 1.2 + 0.2,
      alpha: Math.random() * 0.6 + 0.1,
      speed: Math.random() * 0.0005 + 0.0002,
      phase: Math.random() * Math.PI * 2,
    });
  }
}

function animate() {
  if (!ctx || !canvas) return;

  ctx.clearRect(0, 0, canvas.width, canvas.height);

  const time = Date.now();

  stars.forEach(star => {
    const twinkle = Math.sin(time * star.speed + star.phase) * 0.3 + 0.7;
    const alpha = star.alpha * twinkle;

    ctx.beginPath();
    ctx.arc(star.x, star.y, star.radius, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(0, 245, 255, ${alpha})`;
    ctx.fill();
  });

  animFrame = requestAnimationFrame(animate);
}

/**
 * Cleanup
 */
export function destroyStarField() {
  if (animFrame) cancelAnimationFrame(animFrame);
  if (canvas) canvas.remove();
  window.removeEventListener('resize', resize);
}
