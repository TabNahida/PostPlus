"use strict";
window.PostPlusSize = (() => {
  const units = [{name:"B",factor:1},{name:"KiB",factor:1024},{name:"MiB",factor:1048576},{name:"GiB",factor:1073741824},{name:"TiB",factor:1099511627776}];
  const factor = name => {const unit=units.find(item=>item.name===name);if(!unit) throw new Error("Invalid size unit");return unit.factor;};
  function toBytes(value, unit, min=0, max=Number.MAX_SAFE_INTEGER) {
    const text=String(value).trim();
    if(!/^\d+(?:\.\d+)?$/.test(text)) throw new Error("Invalid size");
    // Decimal parsing with integers avoids rounding fractional bytes silently.
    const [whole,fraction=""]=text.split(".");
    if(text.length>64) throw new Error("Invalid size");
    const scale=10n**BigInt(fraction.length), numerator=BigInt(whole+fraction)*BigInt(factor(unit));
    if(numerator%scale!==0n) throw new Error("Size must be a whole number of bytes");
    const bytes=numerator/scale;
    if(bytes<BigInt(min) || bytes>BigInt(max)) throw new Error("Size is outside the allowed range");
    return Number(bytes);
  }
  function split(bytes) {
    if(!Number.isSafeInteger(bytes) || bytes<0) throw new Error("Invalid size");
    // Use exact, short initial values. Arbitrary byte counts stay exact in B.
    const unit=[...units].reverse().find(item=>bytes>=item.factor && bytes%item.factor===0) || units[0];
    return {value:String(bytes/unit.factor),unit:unit.name};
  }
  function decimal(bytes,unit) {
    const denominator=BigInt(factor(unit)), value=BigInt(bytes);
    let rest=value%denominator, out=String(value/denominator);
    if(rest) {out+=".";while(rest) {rest*=10n;out+=String(rest/denominator);rest%=denominator;}}
    return out;
  }
  function format(bytes) {
    const size=Number(bytes||0),unit=[...units].reverse().find(item=>size>=item.factor)||units[0];
    return `${Number((size/unit.factor).toFixed(2))} ${unit.name}`;
  }
  function create(input,select,bytes,{min=0,max=Number.MAX_SAFE_INTEGER}={}) {
    for(const unit of units) {const option=document.createElement("option");option.value=unit.name;option.textContent=unit.name;select.append(option);}
    input.type="number";input.step="any";input.min="0";
    let previous;
    function set(value) {const initial=split(value);input.value=initial.value;select.value=initial.unit;previous=initial.unit;}
    set(bytes);
    select.addEventListener("change",()=>{
      try {const value=toBytes(input.value,previous);input.value=decimal(value,select.value);previous=select.value;}
      catch {select.value=previous;input.focus();}
    });
    return {read:()=>toBytes(input.value,select.value,min,max),set};
  }
  return {units,split,toBytes,format,create};
})();
