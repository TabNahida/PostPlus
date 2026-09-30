"use strict";
// Keep the configured mail domain visible while accepting saved full usernames.
window.PostPlusAddress = (() => {
  function create(input, suffix) {
    let domain = "", fixedAddress = "", draftDomain = false;
    const validDomain = value => typeof value === "string" && value.length > 0 && value.length <= 253 && value.split(".").every(label => label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label));
    function displayDomain(value) {
      domain = value.toLowerCase();
      if (!fixedAddress) suffix.textContent = domain ? "@" + domain : "";
      normalize();
    }
    function setDomain(value) {
      if (!validDomain(value))
        throw new Error(PostPlusI18n.t("The server returned an unreadable response."));
      draftDomain = false;
      displayDomain(value);
    }
    function setDraftDomain(value) {
      draftDomain = true;
      displayDomain(value.trim());
    }
    function normalize() {
      if (fixedAddress || !domain) return;
      const value = input.value.trim();
      if (value.toLowerCase().endsWith("@" + domain)) input.value = value.slice(0, -(domain.length + 1));
    }
    function address() {
      if (fixedAddress) return fixedAddress;
      if (!domain) throw new Error(PostPlusI18n.t("Could not load the mail domain. Refresh this page and try again."));
      if (!validDomain(domain)) throw new Error(PostPlusI18n.t(draftDomain ? "Enter a valid ASCII mail domain, such as example.com." : "The server returned an unreadable response."));
      normalize();
      const value = input.value.trim().toLowerCase();
      const localSymbols = ".!#$%&'*+-/=?^_`{|}~";
      if (!value || value.length > 64 || value.length + domain.length + 1 > 254 || value.startsWith(".") || value.endsWith(".") || value.includes("..") || [...value].some(char => !(/[a-z0-9]/.test(char) || localSymbols.includes(char))))
        throw new Error(PostPlusI18n.t("Enter a mailbox name on the displayed domain."));
      return value + "@" + domain;
    }
    function setAddress(value = "") {
      fixedAddress = value;
      input.readOnly = Boolean(value);
      input.value = value ? value.slice(0, value.lastIndexOf("@")) : "";
      suffix.textContent = value ? value.slice(value.lastIndexOf("@")) : domain ? "@" + domain : "";
    }
    input.addEventListener("change", normalize);
    return {setDomain, setDraftDomain, setAddress, address};
  }
  return {create};
})();
