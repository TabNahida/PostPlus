"use strict";
// Keep the chosen mail domain visible while accepting saved full usernames.
window.PostPlusAddress = (() => {
  function create(input, suffix) {
    let domain = "", domains = [], fixedAddress = "", draftDomain = false, selector = null;
    const validDomain = value => typeof value === "string" && value.length > 0 && value.length <= 253 && value.split(".").every(label => label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label));
    function displayDomain(value) {
      domain = value.toLowerCase();
      render();
      normalize();
    }
    function render() {
      if (fixedAddress || domains.length < 2 || draftDomain) {
        selector = null;
        suffix.textContent = fixedAddress ? fixedAddress.slice(fixedAddress.lastIndexOf("@")) : domain ? "@" + domain : "";
        return;
      }
      if (!selector) {
        selector = document.createElement("select");
        selector.className = "mailbox-domain-select";
        selector.setAttribute("aria-label",PostPlusI18n.t("Mail domain"));
        for (const value of domains) {
          const option = document.createElement("option"); option.value = value; option.textContent = "@" + value; selector.append(option);
        }
        selector.addEventListener("change",()=>{domain=selector.value;});
        suffix.textContent = ""; suffix.append(selector);
      }
      selector.value = domain;
    }
    function setDomains(values) {
      if (!Array.isArray(values) || !values.length || values.length > 50 || values.some(value=>!validDomain(value)))
        throw new Error(PostPlusI18n.t("The server returned an unreadable response."));
      domains = [...new Set(values.map(value=>value.toLowerCase()))];
      selector = null;
      draftDomain = false;
      displayDomain(domains.includes(domain)?domain:domains[0]);
    }
    function setDomain(value) { setDomains([value]); }
    function setDraftDomain(value) {
      draftDomain = true;
      displayDomain(value.trim());
    }
    function normalize() {
      if (fixedAddress || !domain) return;
      const value = input.value.trim();
      const at = value.lastIndexOf("@"), pasted = value.slice(at+1).toLowerCase();
      if (at >= 0 && !draftDomain && domains.includes(pasted)) {domain=pasted;render();}
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
      selector=null;render();
    }
    input.addEventListener("change", normalize);
    return {setDomain, setDomains, setDraftDomain, setAddress, address};
  }
  return {create};
})();
