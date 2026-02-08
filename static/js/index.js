lucide.createIcons();

if (typeof gsap !== 'undefined' && typeof Draggable !== 'undefined') {
  gsap.registerPlugin(Draggable);
}

if (typeof gsap !== 'undefined' && typeof ScrollTrigger !== 'undefined') {
  gsap.registerPlugin(ScrollTrigger);
}

function toggleAccordion(btn) {
  const item = btn.parentElement;
  item.classList.toggle('nf-accordion-open');
}

function animateHeroIntro() {
  const spans = document.querySelectorAll('h1 span');
  spans.forEach((span, index) => {
    span.style.transform = 'translateY(80px) rotate(5deg)';
    span.style.opacity = '0';
    span.style.transition = 'transform 0.8s ease-out, opacity 0.8s ease-out';

    const delay = 100 + index * 50;
    setTimeout(() => {
      span.style.transform = 'translateY(0) rotate(0deg)';
      span.style.opacity = '1';
    }, delay);
  });

  const card = document.querySelector('.nf-draggable-card');
  if (card) {
    card.style.transform = 'scale(0.8)';
    card.style.opacity = '0';
    card.style.transition = 'transform 0.6s cubic-bezier(0.175, 0.885, 0.32, 1.275), opacity 0.6s ease-out';

    setTimeout(() => {
      card.style.transform = 'scale(1)';
      card.style.opacity = '1';
    }, 300);
  }
}

function setupDraggableCard() {
  if (typeof gsap === 'undefined' || typeof Draggable === 'undefined') return;

  Draggable.create('.nf-draggable-card', {
    type: 'x,y',
    bounds: document.body,
    inertia: false,
    onPress() {
      gsap.to(this.target, { scale: 1.05, duration: 0.15 });
    },
    onRelease() {
      gsap.to(this.target, { scale: 1, duration: 0.15 });
    }
  });
}

function setupStepReveal() {
  const cards = document.querySelectorAll('.nf-step-card');
  if (!('IntersectionObserver' in window) || cards.length === 0) {
    cards.forEach(card => card.classList.add('nf-step-visible'));
    return;
  }

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('nf-step-visible');
        observer.unobserve(entry.target);
      }
    });
  }, {
    threshold: 0.1
  });

  cards.forEach((card) => observer.observe(card));
}

function setupScrollAnimations() {
  const animatedElements = document.querySelectorAll('.nf-fade-up, .nf-fade-in, .nf-slide-left, .nf-slide-right, .nf-scale-in, .nf-stagger-children');
  
  if (!('IntersectionObserver' in window) || animatedElements.length === 0) {
    animatedElements.forEach(el => el.classList.add('nf-visible'));
    return;
  }

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('nf-visible');
        observer.unobserve(entry.target);
      }
    });
  }, {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
  });

  animatedElements.forEach(el => observer.observe(el));
}

function setupGSAPAnimations() {
  if (typeof gsap === 'undefined' || typeof ScrollTrigger === 'undefined') return;

  // Animate section headings (exclude footer)
  gsap.utils.toArray('section h2').forEach(heading => {
    gsap.fromTo(heading, 
      { y: 30, opacity: 0 },
      {
        scrollTrigger: {
          trigger: heading,
          start: 'top 90%',
          toggleActions: 'play none none none'
        },
        y: 0,
        opacity: 1,
        duration: 0.6,
        ease: 'power2.out'
      }
    );
  });

  // Animate footer separately with simple fade
  const footer = document.querySelector('footer');
  if (footer) {
    gsap.fromTo(footer.children, 
      { y: 20, opacity: 0 },
      {
        scrollTrigger: {
          trigger: footer,
          start: 'top 90%',
          toggleActions: 'play none none none'
        },
        y: 0,
        opacity: 1,
        duration: 0.6,
        ease: 'power2.out'
      }
    );
  }

  // Animate grid cards with stagger (exclude footer grids)
  gsap.utils.toArray('section .grid').forEach(grid => {
    const cards = grid.children;
    if (cards.length > 0) {
      gsap.fromTo(cards, 
        { y: 40, opacity: 0 },
        {
          scrollTrigger: {
            trigger: grid,
            start: 'top 85%',
            toggleActions: 'play none none none'
          },
          y: 0,
          opacity: 1,
          duration: 0.5,
          stagger: 0.08,
          ease: 'power2.out'
        }
      );
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  animateHeroIntro();
  setupDraggableCard();
  setupStepReveal();
  setupScrollAnimations();
  setupGSAPAnimations();
});
