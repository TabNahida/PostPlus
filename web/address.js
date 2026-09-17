"use strict";
// Keep the configured mail domain visible while accepting saved full usernames.
window.PostPlusAddress = (() => {
  function create(input, suffix) {
    let domain = "", fixedAddress = "";
    function setDomain(value) {
      if (typeof value !== "string" || !/^[a-z0-9.-]+$/i.test(value) || value.length > 253)
        throw new Error(PostPlusI18n.t("The server returned an unreadable response."));
      domain = value.toLowerCase();
      if (!fixedAddress) suffix.textContent = "@" + domain;
      normalize();
    }
    function normalize() {
      if (fixedAddress || !domain) return;
      const value = input.value.trim();
      if (value.toLowerCase().endsWith("@" + domain)) input.value = value.slice(0, -(domain.length + 1));
    }
    function address() {
      if (fixedAddress) return fixedAddress;
      if (!domain) throw new Error(PostPlusI18n.t("Could not load the mail domain. Refresh this page and try again."));
      normalize();
      const value = input.value.trim().toLowerCase();
      if (!value || value.includes("@")) throw new Error(PostPlusI18n.t("Enter a mailbox name on the displayed domain."));
      return value + "@" + domain;
    }
    function setAddress(value = "") {
      fixedAddress = value;
      input.readOnly = Boolean(value);
      input.value = value ? value.slice(0, value.lastIndexOf("@")) : "";
      suffix.textContent = value ? value.slice(value.lastIndexOf("@")) : domain ? "@" + domain : "";
    }
    input.addEventListener("change", normalize);
    return {setDomain, setAddress, address};
  }
  return {create};
})();
