namespace Malward.NetworkScanner.AdBlock;

public static class AdProcedural
{

    private static readonly string[] Known =
    {
        ":contains(", ":has-text(", ":-abp-contains(", ":-abp-has(", ":if(", ":if-not(",
        ":upward(", ":remove()", ":style(", ":min-text-length(",
        ":matches-css(", ":matches-css-before(", ":matches-css-after(", ":matches-attr(",
        ":matches-path(", ":matches-media(", ":xpath(", ":nth-ancestor(", ":others(",
        ":remove-attr(", ":remove-class("
    };

    public static bool IsProcedural(string sel)
    {
        foreach (var k in Known)
            if (sel.Contains(k, StringComparison.Ordinal)) return true;
        return sel.Contains(":-abp-", StringComparison.Ordinal)
            || sel.Contains(":watch-attr", StringComparison.Ordinal);
    }

    public static bool IsSupported(string sel)
    {
        if (sel.Length is 0 or > 400) return false;
        if (sel.Contains('{') || sel.Contains('}')) return false;
        if (sel.Contains(":watch-attr", StringComparison.Ordinal)) return false;
        if (sel.Contains(":others(", StringComparison.Ordinal)) return false;

        if (sel[0] == '^') return false;
        return true;
    }

    public const string Engine ="""
(function(){
  if(window.__abProcInit) return; window.__abProcInit=1;
  var LIST=[];
  function toRe(s){
    s=String(s);
    if(s.length>1 && s.charAt(0)==='/' && s.lastIndexOf('/')>0){
      var last=s.lastIndexOf('/'); var body=s.slice(1,last); var fl=s.slice(last+1);
      try{ return new RegExp(body, fl.replace(/[^imsu]/g,'')); }catch(e){}
    }
    try{ return new RegExp(s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),'i'); }catch(e){ return null; }
  }
  var PROCEDURALNE={ 'contains':1,'has-text':1,'upward':1,'nth-ancestor':1,'remove':1,
                     'style':1,'min-text-length':1,'matches-css':1,'matches-css-before':1,
                     'matches-css-after':1,'matches-attr':1,'matches-path':1,'matches-media':1,
                     'xpath':1,'if':1,'if-not':1,'remove-attr':1,'remove-class':1 };
  function maProceduralne(s){
    return /:(?:-abp-)?(?:contains|has-text|upward|nth-ancestor|min-text-length|matches-css(?:-before|-after)?|matches-attr|matches-path|matches-media|xpath|if|if-not|remove|remove-attr|remove-class|style)\(/.test(String(s));
  }
  function nazwy(arg){
    var out=[], parts=String(arg||'').split(','), i;
    for(i=0;i<parts.length;i++){
      var t=parts[i].trim().replace(/^["']|["']$/g,'');
      if(!t) continue;
      if(t.length>1 && t.charAt(0)==='/' && t.lastIndexOf('/')>0) out.push(toRe(t));
      else out.push(t);
    }
    return out;
  }
  function parse(sel){
    var ops=[], i=0, css='', dep=0, par=0, quote='';
    while(i<sel.length){
      var c=sel.charAt(i);
      if(quote){ if(c===quote) quote=''; css+=c; i++; continue; }
      if(c==='"'||c==="'"){ quote=c; css+=c; i++; continue; }
      if(c==='['){ dep++; css+=c; i++; continue; }
      if(c===']'){ dep--; css+=c; i++; continue; }
      if(c==='('){ par++; css+=c; i++; continue; }
      if(c===')'){ par--; css+=c; i++; continue; }
      if(c===':' && dep===0 && par===0){
        var m=/^:(-abp-)?([a-z-]+)\(/.exec(sel.slice(i));
        var nazwa = m ? m[2] : null;
        var zagniezdzone = m && (nazwa==='has'||nazwa==='not');
        if(m && (PROCEDURALNE[nazwa] || zagniezdzone)){
          var start=i+m[0].length, d=1, j=start, q2='';
          while(j<sel.length && d>0){
            var ch=sel.charAt(j);
            if(q2){ if(ch===q2) q2=''; }
            else if(ch==='"'||ch==="'") q2=ch;
            else if(ch==='(') d++;
            else if(ch===')') d--;
            if(d>0) j++;
          }
          var arg=sel.slice(start,j);
          if(zagniezdzone && !m[1] && !maProceduralne(arg)){
            css+=sel.slice(i, j+1); i=j+1; continue;
          }
          ops.push({ n:nazwa, a:arg, zagn:!!zagniezdzone });
          i=j+1; continue;
        }
        if(/^:remove\(\)/.test(sel.slice(i))){ ops.push({n:'remove',a:''}); i+=9; continue; }
      }
      css+=c; i++;
    }
    return { css: css.trim(), ops: ops };
  }
  var PARSED={};
  function parseCached(sel){
    var hit=PARSED[sel];
    if(hit===undefined){ hit=parse(sel); PARSED[sel]=hit; }
    return hit;
  }
  function pasujeWewnatrz(el, sel){
    var rec = parseCached(sel);
    var css = rec.css || '*';
    if(/^[>+~]/.test(css)) css = ':scope ' + css;
    var kand;
    try{ kand = el.querySelectorAll(css); }catch(e){ return false; }
    var zbior=[]; for(var i=0;i<kand.length && i<2000;i++) zbior.push(kand[i]);
    if(!rec.ops.length) return zbior.length>0;
    return filtruj(zbior, rec.ops, true).length>0;
  }
  function tekst(el){ try{ return el.innerText || el.textContent || ''; }catch(e){ return ''; } }
  function zastosuj(el, akcja, styl, arg){
    try{
      if(akcja==='remove'){ el.remove(); return; }
      if(akcja==='remove-attr'){
        var atrybuty=el.attributes, i, j;
        for(i=atrybuty.length-1;i>=0;i--){
          var an=atrybuty[i].name;
          for(j=0;j<arg.length;j++){
            var wzA=arg[j];
            if(wzA && wzA.test ? wzA.test(an) : an===wzA){ el.removeAttribute(an); break; }
          }
        }
        return;
      }
      if(akcja==='remove-class'){
        var klasy=[], k, m;
        for(k=0;k<el.classList.length;k++) klasy.push(el.classList[k]);
        for(k=0;k<klasy.length;k++){
          for(m=0;m<arg.length;m++){
            var wzK=arg[m];
            if(wzK && wzK.test ? wzK.test(klasy[k]) : klasy[k]===wzK){ el.classList.remove(klasy[k]); break; }
          }
        }
        return;
      }
      var S=window.__abStyle;
      if(akcja==='style' && styl){
        if(S && S.apply(el, styl)) return;
        var pary=styl.split(';');
        for(var i=0;i<pary.length;i++){
          var kv=pary[i].split(':');
          if(kv.length<2) continue;
          el.style.setProperty(kv[0].trim(), kv.slice(1).join(':').trim(), 'important');
        }
        return;
      }
      if(S){
        if(S.marked(el)) return;
        if(S.apply(el,'display:none!important')) return;
      }
      if(el.style.getPropertyValue('display')==='none') return;
      el.style.setProperty('display','none','important');
    }catch(e){}
  }
  function filtruj(zbior, ops, tylkoFiltr, rec){
    for(var o=0;o<ops.length;o++){
      var op=ops[o], nast=[];
      if(op.n==='matches-path'){
        var reSciezka=op.re||(op.re=toRe(op.a));
        if(!(reSciezka && reSciezka.test(location.pathname+location.search))) return [];
        continue;
      }
      if(op.n==='matches-media'){
        var media=op.mq;
        if(media===undefined){
          try{ media=op.mq=window.matchMedia(String(op.a).replace(/^["']|["']$/g,'')); }
          catch(e){ media=op.mq=null; }
        }
        if(!(media && media.matches)) return [];
        continue;
      }
      for(var k=0;k<zbior.length;k++){
        var el=zbior[k];
        try{
          switch(op.n){
            case 'contains': case 'has-text': {
              var re=op.re||(op.re=toRe(op.a));
              if(re && re.test(tekst(el))) nast.push(el);
              break; }
            case 'min-text-length':
              if(tekst(el).length >= (parseInt(op.a,10)||0)) nast.push(el);
              break;
            case 'has': case 'if':
              if(pasujeWewnatrz(el, op.a)) nast.push(el);
              break;
            case 'not': case 'if-not':
              if(!pasujeWewnatrz(el, op.a)) nast.push(el);
              break;
            case 'upward': case 'nth-ancestor': {
              var n=parseInt(op.a,10);
              if(!isNaN(n)){ var p=el; for(var z=0;z<n&&p;z++) p=p.parentElement; if(p) nast.push(p); }
              else { var c2=el.closest(op.a); if(c2) nast.push(c2); }
              break; }
            case 'matches-css': case 'matches-css-before': case 'matches-css-after': {
              var pe = op.n==='matches-css-before' ? '::before'
                     : op.n==='matches-css-after' ? '::after' : null;
              var ix=op.a.indexOf(':');
              if(ix<0) break;
              var prop=op.a.slice(0,ix).trim(), oczek=op.a.slice(ix+1).trim();
              var st=getComputedStyle(el, pe);
              var wart=st?st.getPropertyValue(prop):'';
              var re2=toRe(oczek);
              if(re2 && re2.test(String(wart).trim())) nast.push(el);
              break; }
            case 'matches-attr': {
              var mm=/^"?([^"=]+)"?(?:=(.*))?$/.exec(op.a);
              if(!mm) break;
              var nazwaAtr=mm[1].trim();
              if(mm[2]===undefined){ if(el.hasAttribute(nazwaAtr)) nast.push(el); break; }
              var re3=toRe(mm[2].replace(/^"|"$/g,''));
              if(re3 && re3.test(el.getAttribute(nazwaAtr)||'')) nast.push(el);
              break; }
            case 'xpath': {
              var wynik=document.evaluate(op.a, el, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
              for(var q=0;q<wynik.snapshotLength;q++) nast.push(wynik.snapshotItem(q));
              break; }
            case 'remove': if(!tylkoFiltr && rec) rec.akcja='remove'; nast.push(el); break;
            case 'style': if(!tylkoFiltr && rec){ rec.akcja='style'; rec.styl=op.a; } nast.push(el); break;
            case 'remove-attr': case 'remove-class':
              if(!tylkoFiltr && rec){ rec.akcja=op.n; rec.arg=op.lista||(op.lista=nazwy(op.a)); }
              nast.push(el); break;
            default: break;
          }
        }catch(e){}
      }
      zbior=nast;
      if(zbior.length===0) break;
    }
    return zbior;
  }
  var MAX_SET=2000, MAX_BATCH_SET=12000;
  function kandydaci(rec, dodane){
    var css = rec.css || '*';
    if(!dodane){
      try{ return document.querySelectorAll(css); }catch(e){ rec.zle=1; return null; }
    }
    var out=[];
    for(var i=0;i<dodane.length && out.length<MAX_BATCH_SET;i++){
      var a=dodane[i];
      if(!a || a.nodeType!==1) continue;
      try{
        if(a.matches(css)) out.push(a);
        var kids=a.querySelectorAll(css);
        for(var j=0;j<kids.length && out.length<MAX_BATCH_SET;j++) out.push(kids[j]);
      }catch(e){}
    }
    return out;
  }
  function wykonaj(rec, dodane){
    var baza = kandydaci(rec, dodane);
    if(!baza) return false;
    var start = dodane ? 0 : (rec.kursor||0);
    var limit = dodane ? MAX_BATCH_SET : BUDGET;
    var zbior=[];
    for(var i=start;i<baza.length && zbior.length<limit;i++) zbior.push(baza[i]);
    var koniec = dodane ? true : (start + zbior.length >= baza.length);
    rec.kursor = koniec ? 0 : start + zbior.length;
    if(zbior.length){
      zbior = filtruj(zbior, rec.ops, false, rec);
      for(var w=0;w<zbior.length;w++) zastosuj(zbior[w], rec.akcja, rec.styl, rec.arg);
      rec.trafienia=(rec.trafienia||0)+zbior.length;
    }
    return !koniec;
  }
  var oczekuje=false, kolejka=null, pelny=false;
  var BUDGET=1500, QUEUE_CEILING=20000, PUMP_MS=40, IDLE_MS=120;
  function przebieg(dodane){
    var wiecej=false;
    for(var i=0;i<LIST.length;i++){
      if(LIST[i].zle) continue;
      try{ if(wykonaj(LIST[i], dodane)) wiecej=true; }catch(e){}
    }
    return wiecej;
  }
  function pompa(){
    oczekuje=false;
    var porcja=null;
    if(pelny){ pelny=false; kolejka=null; }
    else if(kolejka){
      if(kolejka.length>BUDGET){ porcja=kolejka.slice(0,BUDGET); kolejka=kolejka.slice(BUDGET); }
      else { porcja=kolejka; kolejka=null; }
    }
    var wiecej = przebieg(porcja);
    if((kolejka && kolejka.length) || wiecej) uzbroj(PUMP_MS);
  }
  function uzbroj(ms){ if(oczekuje) return; oczekuje=true; setTimeout(pompa, ms); }
  function zaplanuj(dodane){
    if(dodane){
      if(!kolejka) kolejka=[];
      for(var i=0;i<dodane.length;i++) kolejka.push(dodane[i]);
      if(kolejka.length>QUEUE_CEILING){ kolejka=null; pelny=true; }
    } else pelny=true;
    uzbroj(IDLE_MS);
  }
  window.__abProcStats=function(){
    var trafienia=0, zle=0;
    for(var i=0;i<LIST.length;i++){ trafienia+=(LIST[i].trafienia||0); if(LIST[i].zle) zle++; }
    return {rules:LIST.length, hits:trafienia, broken:zle, parsed:Object.keys(PARSED).length,
            queued:kolejka?kolejka.length:0, fullPending:pelny};
  };
  window.__abProc=function(selektory){
    try{
      for(var i=0;i<selektory.length;i++){
        var rec=parse(selektory[i]);
        if(!rec.ops.length) continue;
        rec.akcja='hide'; rec.raw=selektory[i];
        LIST.push(rec);
      }
      window.__abProcCount=LIST.length;
      przebieg();
      if(document.readyState==='loading')
        document.addEventListener('DOMContentLoaded', przebieg);
      if(window.__abObs) window.__abObs(zaplanuj);
      else { try{ new MutationObserver(function(){ zaplanuj(); })
                    .observe(document.documentElement,{childList:true, subtree:true}); }catch(e){} }
      setTimeout(przebieg, 700); setTimeout(przebieg, 2000); setTimeout(przebieg, 4500);
    }catch(e){}
  };
})();
""";
}
