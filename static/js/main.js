
document.addEventListener("DOMContentLoaded", function () {

 
  const overlay = document.getElementById("loading-overlay");

  function showLoading() {
    if (overlay) overlay.classList.add("active");
  }


  const scanForms = document.querySelectorAll(".scan-form");
  scanForms.forEach(function (form) {
    form.addEventListener("submit", function (e) {
 
      const isValid = validateForm(form);
      if (isValid) {
        showLoading();
      }
    });
  });


  const reportForm = document.getElementById("reportForm");
  if (reportForm) {
    reportForm.addEventListener("submit", function (e) {
      const isValid = validateReportForm();
      if (isValid) showLoading();
    });
  }



  function validateForm(form) {
    const formId = form.id;

    if (formId === "form-message") {
      const textarea = document.getElementById("message_text");
      if (!textarea || textarea.value.trim().length < 5) {
        showError(textarea, "Please paste a message (minimum 5 characters) before scanning.");
        return false;
      }
    }

    if (formId === "form-link") {
      const input = document.getElementById("url_input");
      if (!input || input.value.trim().length < 4) {
        showError(input, "Please paste a URL before scanning.");
        return false;
      }
    }

    if (formId === "form-screenshot") {
      const fileInput = document.getElementById("file_input");
      if (!fileInput || fileInput.files.length === 0) {
        alert("Please select an image file before scanning.");
        return false;
      }
    }

    return true;
  }

  function validateReportForm() {
    const content = document.getElementById("report_content");
    const type    = document.getElementById("report_type");

    if (type && !type.value) {
      alert("Please select a scam type.");
      type.focus();
      return false;
    }
    if (content && content.value.trim().length < 10) {
      showError(content, "Please provide more detail (minimum 10 characters).");
      return false;
    }
    return true;
  }

  function showError(element, message) {
    alert(message);
    if (element) element.focus();
  }


 
  const msgTextarea = document.getElementById("message_text");
  const msgCount    = document.getElementById("msg-count");

  if (msgTextarea && msgCount) {
    msgTextarea.addEventListener("input", function () {
      const len = this.value.length;
      msgCount.textContent = len;
      msgCount.style.color = len > 4500 ? "#ff9500" : "";
    });
  }


  const reportTextarea = document.getElementById("report_content");
  const reportCount    = document.getElementById("report-count");

  if (reportTextarea && reportCount) {
    reportTextarea.addEventListener("input", function () {
      const len = this.value.length;
      reportCount.textContent = len;
      reportCount.style.color = len > 9000 ? "#ff9500" : "";
    });
  }



  const fileInput  = document.getElementById("file_input");
  const dropContent = document.getElementById("dropContent");
  const fileDrop   = document.getElementById("fileDrop");

  if (fileInput && dropContent) {
    fileInput.addEventListener("change", function () {
      const file = this.files[0];
      if (file) {
       
        const sizeMB = (file.size / (1024 * 1024)).toFixed(2);
        dropContent.innerHTML = `
          <span class="drop-icon"></span>
          <span class="drop-text" style="color: #00e676;">${file.name}</span>
          <span class="drop-sub">${sizeMB} MB — Ready to scan</span>
        `;
      }
    });
  }


  if (fileDrop) {
    fileDrop.addEventListener("dragover", function (e) {
      e.preventDefault();
      this.classList.add("drag-over");
    });
    fileDrop.addEventListener("dragleave", function () {
      this.classList.remove("drag-over");
    });
    fileDrop.addEventListener("drop", function (e) {
      e.preventDefault();
      this.classList.remove("drag-over");
      const files = e.dataTransfer.files;
      if (files.length > 0 && fileInput) {
        fileInput.files = files;
        fileInput.dispatchEvent(new Event("change"));
      }
    });
  }



  const navToggle = document.getElementById("navToggle");
  const mobileNav = document.getElementById("mobileNav");

  if (navToggle && mobileNav) {
    navToggle.addEventListener("click", function () {
      mobileNav.classList.toggle("open");
    });
    
    mobileNav.querySelectorAll(".mob-link").forEach(function (link) {
      link.addEventListener("click", function () {
        mobileNav.classList.remove("open");
      });
    });
  }



  const fills = document.querySelectorAll(".meter-fill, .dbar-safe, .dbar-suspicious, .dbar-dangerous");
  fills.forEach(function (el) {
    const targetWidth = el.style.width;
    el.style.width    = "0%";
    setTimeout(function () {
      el.style.width = targetWidth;
    }, 300);
  });



  const cardHeaders = document.querySelectorAll(".card-header");
  cardHeaders.forEach(function (header) {
    header.addEventListener("click", function () {
      const card  = this.closest(".scan-card");
      const input = card.querySelector("textarea, input[type='text']");
      if (input) input.focus();
    });
  });

});
