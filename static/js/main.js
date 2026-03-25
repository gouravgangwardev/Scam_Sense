document.addEventListener("DOMContentLoaded", function () {

  // ── Loading Overlay ─────────────────────────────────────────────────────
  const overlay = document.getElementById("loading-overlay");

  function showLoading() {
    if (overlay) overlay.classList.add("active");
  }

  // ── Scan Form Submissions ────────────────────────────────────────────────
  const scanForms = document.querySelectorAll(".scan-form");
  scanForms.forEach(function (form) {
    form.addEventListener("submit", function (e) {
      const isValid = validateForm(form);
      if (!isValid) {
        e.preventDefault();
      } else {
        showLoading();
      }
    });
  });

  // ── Report Form Submission ───────────────────────────────────────────────
  const reportForm = document.getElementById("reportForm");
  if (reportForm) {
    reportForm.addEventListener("submit", function (e) {
      const isValid = validateReportForm();
      if (!isValid) {
        e.preventDefault();
      } else {
        showLoading();
      }
    });
  }

  // ── Form Validation ──────────────────────────────────────────────────────
  function validateForm(form) {
    const formId = form.id;

    if (formId === "form-message") {
      const textarea = document.getElementById("message_text");
      if (!textarea || textarea.value.trim().length < 5) {
        showInlineError(textarea, "Please paste a message (minimum 5 characters) before scanning.");
        return false;
      }
      clearInlineError(textarea);
    }

    if (formId === "form-link") {
      const input = document.getElementById("url_input");
      if (!input || input.value.trim().length < 4) {
        showInlineError(input, "Please paste a URL before scanning.");
        return false;
      }
      clearInlineError(input);
    }

    if (formId === "form-screenshot") {
      const fileInput = document.getElementById("file_input");
      if (!fileInput || fileInput.files.length === 0) {
        showFileError("Please select an image file before scanning.");
        return false;
      }

      const file = fileInput.files[0];
      const allowed = ["image/jpeg", "image/jpg", "image/png"];
      if (!allowed.includes(file.type)) {
        showFileError("Only JPG and PNG files are supported.");
        return false;
      }

      const maxSizeMB = 5;
      if (file.size > maxSizeMB * 1024 * 1024) {
        showFileError("File is too large. Maximum size is 5 MB.");
        return false;
      }

      clearFileError();
    }

    return true;
  }

  function validateReportForm() {
    const content = document.getElementById("report_content");
    const type    = document.getElementById("report_type");

    if (type && !type.value) {
      showInlineError(type, "Please select a scam type.");
      type.focus();
      return false;
    }
    if (content && content.value.trim().length < 10) {
      showInlineError(content, "Please provide more detail (minimum 10 characters).");
      return false;
    }
    clearInlineError(content);
    return true;
  }

  // ── Inline Error Helpers ─────────────────────────────────────────────────
  function showInlineError(element, message) {
    if (!element) return;

    // Remove existing error for this element
    const existingError = element.parentElement.querySelector(".inline-error");
    if (existingError) existingError.remove();

    const errorEl = document.createElement("p");
    errorEl.className  = "inline-error";
    errorEl.textContent = "⚠ " + message;
    errorEl.style.cssText = "color:#ff9500;font-size:11px;margin-top:6px;font-family:monospace;letter-spacing:1px;";

    element.parentElement.appendChild(errorEl);
    element.focus();

    // Remove error on next user input
    element.addEventListener("input", function () {
      clearInlineError(element);
    }, { once: true });
  }

  function clearInlineError(element) {
    if (!element) return;
    const existingError = element.parentElement.querySelector(".inline-error");
    if (existingError) existingError.remove();
  }

  function showFileError(message) {
    const dropContent = document.getElementById("dropContent");
    if (!dropContent) return;

    const existingError = document.querySelector(".file-error");
    if (existingError) existingError.remove();

    const errorEl = document.createElement("p");
    errorEl.className  = "file-error";
    errorEl.textContent = "⚠ " + message;
    errorEl.style.cssText = "color:#ff9500;font-size:11px;margin-top:8px;font-family:monospace;letter-spacing:1px;";

    dropContent.parentElement.parentElement.appendChild(errorEl);
  }

  function clearFileError() {
    const existingError = document.querySelector(".file-error");
    if (existingError) existingError.remove();
  }

  // ── Auto-prepend https:// on URL input blur ──────────────────────────────
  const urlInput = document.getElementById("url_input");
  if (urlInput) {
    urlInput.addEventListener("blur", function () {
      const val = this.value.trim();
      if (val && !val.startsWith("http://") && !val.startsWith("https://")) {
        // Strip leading https:// if user accidentally typed it (visible prefix shown in UI)
        this.value = val.replace(/^https?:\/\//i, "");
      }
    });
  }

  // ── Message Character Counter ────────────────────────────────────────────
  const msgTextarea = document.getElementById("message_text");
  const msgCount    = document.getElementById("msg-count");

  if (msgTextarea && msgCount) {
    msgTextarea.addEventListener("input", function () {
      const len = this.value.length;
      msgCount.textContent = len;
      msgCount.style.color = len > 4500 ? "#ff9500" : "";
    });
  }

  // ── Report Character Counter ─────────────────────────────────────────────
  const reportTextarea = document.getElementById("report_content");
  const reportCount    = document.getElementById("report-count");

  if (reportTextarea && reportCount) {
    reportTextarea.addEventListener("input", function () {
      const len = this.value.length;
      reportCount.textContent = len;
      reportCount.style.color = len > 9000 ? "#ff9500" : "";
    });
  }

  // ── File Drop Zone ───────────────────────────────────────────────────────
  const fileInput   = document.getElementById("file_input");
  const dropContent = document.getElementById("dropContent");
  const fileDrop    = document.getElementById("fileDrop");

  if (fileInput && dropContent) {
    fileInput.addEventListener("change", function () {
      const file = this.files[0];
      if (file) {
        const sizeMB   = (file.size / (1024 * 1024)).toFixed(2);
        const allowed  = ["image/jpeg", "image/jpg", "image/png"];
        const isValid  = allowed.includes(file.type) && file.size <= 5 * 1024 * 1024;

        if (!isValid) {
          dropContent.innerHTML = `
            <span class="drop-icon">⚠️</span>
            <span class="drop-text" style="color:#ff9500;">${file.name}</span>
            <span class="drop-sub" style="color:#ff9500;">Invalid file — JPG/PNG under 5MB only</span>
          `;
        } else {
          dropContent.innerHTML = `
            <span class="drop-icon">✅</span>
            <span class="drop-text" style="color:#00e676;">${file.name}</span>
            <span class="drop-sub">${sizeMB} MB — Ready to scan</span>
          `;
          clearFileError();
        }
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

  // ── Mobile Nav Toggle ────────────────────────────────────────────────────
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

  // ── Animate Risk Meter Bars ──────────────────────────────────────────────
  const fills = document.querySelectorAll(".meter-fill, .dbar-safe, .dbar-suspicious, .dbar-dangerous");
  fills.forEach(function (el) {
    const targetWidth = el.style.width;
    el.style.width    = "0%";
    setTimeout(function () {
      el.style.width = targetWidth;
    }, 300);
  });

  // ── Card Header Click Focus ──────────────────────────────────────────────
  const cardHeaders = document.querySelectorAll(".card-header");
  cardHeaders.forEach(function (header) {
    header.addEventListener("click", function () {
      const card  = this.closest(".scan-card");
      const input = card.querySelector("textarea, input[type='text']");
      if (input) input.focus();
    });
  });

});
