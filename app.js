// App logic for Hacienda Catalina Coclé website matching live site specifications

document.addEventListener('DOMContentLoaded', () => {

  // Mobile Menu Drawer Toggle
  const menuToggle = document.getElementById('menuToggle');
  const mobileNav = document.getElementById('mobileNav');

  if (menuToggle && mobileNav) {
    menuToggle.addEventListener('click', () => {
      mobileNav.classList.toggle('active');
      const icon = menuToggle.querySelector('i');
      if (mobileNav.classList.contains('active')) {
        icon.classList.remove('fa-bars');
        icon.classList.add('fa-xmark');
      } else {
        icon.classList.remove('fa-xmark');
        icon.classList.add('fa-bars');
      }
    });

    mobileNav.querySelectorAll('a').forEach(link => {
      link.addEventListener('click', () => {
        mobileNav.classList.remove('active');
        const icon = menuToggle.querySelector('i');
        if (icon) {
          icon.classList.remove('fa-xmark');
          icon.classList.add('fa-bars');
        }
      });
    });
  }

  // Header scroll state
  const header = document.getElementById('mainHeader');
  window.addEventListener('scroll', () => {
    if (window.scrollY > 50) {
      header.style.background = 'rgba(10, 18, 12, 0.95)';
      header.style.boxShadow = '0 10px 30px rgba(0,0,0,0.5)';
    } else {
      header.style.background = 'rgba(10, 18, 12, 0.85)';
      header.style.boxShadow = 'none';
    }
  });

  // Handle Form Submissions with Enterprise Security Engine
  const forms = ['heroForm', 'contactoForm'];
  forms.forEach(formId => {
    const form = document.getElementById(formId);
    if (!form) return;

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const submitBtn = form.querySelector('button[type="submit"]');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.style.opacity = '0.7';
        submitBtn.innerHTML = '<span>Verificando Seguridad...</span> <i class="fa-solid fa-spinner fa-spin"></i>';
      }

      // Execute Enterprise Security Submission (PoW, HMAC CSRF, Honeypot & WAF validation)
      const res = await window.HaciendaSecurity.submitSecureForm(form);

      if (!res.success) {
        alert('⚠️ ' + (res.message || 'Error al procesar la solicitud de forma segura.'));
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.style.opacity = '1';
          submitBtn.innerHTML = '<span>Agendar Reunión</span> <i class="fa-solid fa-arrow-right"></i>';
        }
        return;
      }

      const nombre = res.data.nombre || 'Estimado Cliente';
      const refCode = res.data.ref || 'HC-SECURE';
      const card = form.closest('.glass-card');
      if (!card) return;

      card.innerHTML = `
        <div style="text-align: center; padding: 2.5rem 1rem;">
          <div style="width: 64px; height: 64px; background: rgba(216, 168, 104, 0.15); border: 1px solid rgba(216, 168, 104, 0.3); color: #d8a868; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; font-size: 2rem; margin-bottom: 1.25rem;">
            <i class="fa-solid fa-shield-halved"></i>
          </div>
          <h3 style="font-family: 'Cormorant Garamond', serif; font-size: 2.2rem; font-weight: 600; margin-bottom: 0.5rem; color: #f4f3ef;">¡Solicitud Verificada y Cifrada!</h3>
          <p style="color: #91a093; font-size: 0.95rem; margin-bottom: 0.75rem; line-height: 1.6;">Gracias <strong>${nombre}</strong>, tu solicitud ha sido registrada bajo el código de confirmación opaco <strong style="color: #d8a868;">${refCode}</strong>.</p>
          <p style="color: #6c7a6e; font-size: 0.82rem; margin-bottom: 1.75rem;">Nuestro equipo comercial de Hacienda Catalina Coclé se comunicará vía WhatsApp a la brevedad.</p>
          <button id="reset_${formId}" class="btn-submit-gold" style="margin: 0 auto; display: inline-flex; padding: 0.75rem 1.5rem; font-size: 0.88rem;">Enviar otra solicitud</button>
        </div>
      `;

      const resetBtn = document.getElementById(`reset_${formId}`);
      if (resetBtn) {
        resetBtn.addEventListener('click', () => {
          card.innerHTML = originalContent;
          // Re-bind listener on recreated form
          const newForm = document.getElementById(formId);
          if (newForm) {
            newForm.addEventListener('submit', (ev) => ev.preventDefault());
          }
        });
      }
    });
  });

});
