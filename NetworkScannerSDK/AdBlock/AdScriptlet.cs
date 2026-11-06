using System.Text;

namespace Malward.NetworkScanner.AdBlock;

public static class AdScriptlet
{

    private const string Library ="""
(function(){
  if(window.__abScr) return; window.__abScr=1; var W=window;
  W.__abStyle = W.__abStyle || (function(){
    function rnd(){
      var a=parseInt('a000000000',36), b=parseInt('zzzzzzzzzz',36);
      return 'd'+Math.floor(Math.random()*(b-a)+a).toString(36);
    }
    var globalAttr=rnd(), rules={}, sheet=null, fallback=null, ready=false;
    function ensure(){
      if(ready) return;
      ready=true;
      try{
        if(W.CSSStyleSheet && 'adoptedStyleSheets' in document){
          sheet=new W.CSSStyleSheet();
          document.adoptedStyleSheets=document.adoptedStyleSheets.concat([sheet]);
          return;
        }
      }catch(e){ sheet=null; }
      try{
        fallback=document.createElement('style');
        (document.head||document.documentElement).appendChild(fallback);
      }catch(e){ fallback=null; }
    }
    function addRule(css){
      ensure();
      try{
        if(sheet){ sheet.insertRule(css, sheet.cssRules.length); return true; }
        if(fallback){ fallback.appendChild(document.createTextNode(css)); return true; }
      }catch(e){}
      return false;
    }
    function attrFor(decl){
      var a=rules[decl];
      if(a) return a;
      a=rnd();
      if(!addRule('['+globalAttr+']['+a+']{'+decl+'}')) return null;
      rules[decl]=a;
      return a;
    }
    var statics={};
    function hideOne(sel){
      if(!sel) return false;
      if(statics[sel]) return statics[sel]===1;
      statics[sel] = addRule(sel+'{display:none!important}') ? 1 : 2;
      return statics[sel]===1;
    }
    return {
      hide:function(sel){
        var list = (typeof sel==='string') ? [sel] : (sel||[]);
        if(!list.length) return false;
        if(list.length>1 && hideOne(list.join(','))) return true;
        var any=false;
        for(var i=0;i<list.length;i++) if(hideOne(list[i])) any=true;
        return any;
      },
      marked:function(el){ try{ return el.hasAttribute(globalAttr); }catch(e){ return false; } },
      apply:function(el, decl){
        var a=attrFor(decl);
        if(a===null) return false;
        try{
          var inline=el.getAttribute('style');
          if(inline && inline.indexOf('!important')>=0) return false;
          el.setAttribute(globalAttr,''); el.setAttribute(a,'');
          return true;
        }catch(e){ return false; }
      },
      stats:function(){ var n=0, s=0;
        for(var k in rules) n++;
        for(var j in statics) if(statics[j]===1) s++;
        return {attr:globalAttr, rules:n, statics:s, adopted:!!sheet, fallback:!!fallback}; }
    };
  })();

  W.__abObs = W.__abObs || (function(){
    var subs=[], mo=null, attached=false, poll=0, resumeAt=0;
    var pending=false, batch=[], score=0, frameStart=0, overflowed=false;
    var SCORE_LIMIT=900, FRAME_MS=1000, POLL_MS=500, CALM_MS=10000, MAX_BATCH=2000;
    function soon(fn){
      try{ if(W.requestIdleCallback) return W.requestIdleCallback(fn,{timeout:250}); }catch(e){}
      return setTimeout(fn,40);
    }
    function deliver(){
      pending=false;
      var added = (overflowed || !batch.length) ? null : batch;
      batch = []; overflowed=false;
      for(var i=0;i<subs.length;i++){ try{ subs[i](added); }catch(e){} }
    }
    function schedule(){ if(pending) return; pending=true; soon(deliver); }
    function attach(){
      if(attached) return;
      try{
        mo=new MutationObserver(onRecords);
        mo.observe(document.documentElement,
                   {childList:true,subtree:true,attributeFilter:['id','class','href']});
        attached=true; frameStart=Date.now(); score=0;
      }catch(e){}
    }
    function detach(){
      if(mo){ try{ mo.disconnect(); }catch(e){} }
      attached=false; batch=[]; overflowed=true; resumeAt=Date.now()+CALM_MS;
      if(poll) return;
      poll=setInterval(function(){
        if(Date.now()>=resumeAt){ clearInterval(poll); poll=0; attach(); }
        schedule();
      }, POLL_MS);
    }
    function onRecords(recs){
      var now=Date.now();
      if(now>frameStart+FRAME_MS){ frameStart=now; score=0; }
      score+=recs.length;
      for(var i=0;i<recs.length;i++){
        var a=recs[i].addedNodes;
        for(var j=0;a&&j<a.length;j++){
          if(a[j].nodeType!==1) continue;
          if(batch.length>=MAX_BATCH){ overflowed=true; break; }
          batch.push(a[j]);
        }
      }
      if(score>SCORE_LIMIT) detach();
      schedule();
    }
    W.__abObsState = function(){ return {attached:attached, polling:!!poll, subs:subs.length,
                                         score:score, batch:batch.length, overflowed:overflowed}; };
    return function(fn){
      if(typeof fn!=='function') return;
      subs.push(fn);
      attach();
      try{ fn(null); }catch(e){}
    };
  })();
  function pv(v){ if(v==='true')return true; if(v==='false')return false; if(v==='null')return null;
    if(v==='undefined')return undefined; if(v==='noopFunc'||v==='')return function(){};
    if(v==='trueFunc')return function(){return true;}; if(v==='falseFunc')return function(){return false;};
    if(v==='emptyArr')return []; if(v==='emptyObj')return {}; if(/^-?\d+(\.\d+)?$/.test(v))return Number(v); return v; }
  var CHAINS = new WeakMap();
  function chainRec(owner,p){
    var m = CHAINS.get(owner); if(!m){ m = new Map(); CHAINS.set(owner,m); }
    var rec = m.get(p);
    if(rec) return rec;
    rec = { has:false, val:undefined, kids:[], leaf:false, leafVal:undefined };
    try{ var d = Object.getOwnPropertyDescriptor(owner,p);
         if(d && 'value' in d){ rec.has = true; rec.val = d.value; } }catch(e){}
    try{
      Object.defineProperty(owner,p,{ configurable:true,
        get:function(){ return rec.leaf ? rec.leafVal : rec.val; },
        set:function(nv){
          if(rec.leaf) return;
          rec.has = true; rec.val = nv;
          if(nv && (typeof nv==='object' || typeof nv==='function'))
            for(var i=0;i<rec.kids.length;i++){ try{ rec.kids[i](nv); }catch(e){} }
        }});
    }catch(e){ rec.broken = true; }
    m.set(p,rec);
    return rec;
  }
  function setConstant(chain,val){ var v=pv(val); var parts=String(chain).split('.');
    function ins(owner,i){
      if(owner==null) return;
      var p = parts[i];
      if(i===parts.length-1){
        var rec = chainRec(owner,p);
        if(rec.broken){ try{owner[p]=v;}catch(e){} return; }
        rec.leaf = true; rec.leafVal = v; return;
      }
      var cur; try{ cur = owner[p]; }catch(e){ cur = null; }
      if(cur && (typeof cur==='object' || typeof cur==='function')){ ins(cur,i+1); return; }
      var rec2 = chainRec(owner,p);
      if(rec2.broken) return;
      rec2.kids.push(function(o){ ins(o,i+1); });
    }
    ins(W,0); }
  function aopr(chain){ var parts=String(chain).split('.');
    function ins(owner,i){ if(owner==null)return; var p=parts[i];
      if(i===parts.length-1){ try{Object.defineProperty(owner,p,{configurable:false,get:function(){throw new ReferenceError(p);}});}catch(e){} return; }
      var o; try{o=owner[p];}catch(e){return;} if(o)ins(o,i+1); }
    ins(W,0); }
  function removeAttr(attrs,sel){ var a=String(attrs).split('|');
    function run(){ try{ var els=document.querySelectorAll(sel||'['+a.join('],[')+']');
      for(var i=0;i<els.length;i++)for(var j=0;j<a.length;j++)els[i].removeAttribute(a[j]); }catch(e){} }
    W.__abObs(run); }
  function removeClass(classes,sel){ var a=String(classes).split('|');
    function run(){ try{ var els=document.querySelectorAll(sel||a.map(function(c){return '.'+c;}).join(','));
      for(var i=0;i<els.length;i++)for(var j=0;j<a.length;j++)
        if(els[i].classList.contains(a[j])) els[i].classList.remove(a[j]); }catch(e){} }
    W.__abObs(run); }
  function hasPath(o,path,i){ if(o==null)return false; if(i>=path.length)return true;
    var k=path[i];
    if(k==='[]'||k==='*'){ if(Array.isArray(o)){ for(var a=0;a<o.length;a++) if(hasPath(o[a],path,i+1))return true; return false; }
      for(var kk in o) if(hasPath(o[kk],path,i+1))return true; return false; }
    if(!(typeof o==='object'))return false; if(!(k in o))return false; return hasPath(o[k],path,i+1); }
  function prunePath(o,path,i){ if(o==null||typeof o!=='object')return;
    var k=path[i];
    if(i===path.length-1){
      if(k==='[]'||k==='*'){ if(Array.isArray(o)){o.length=0;} else {for(var kk in o)delete o[kk];} }
      else if(Array.isArray(o)){ var idx=parseInt(k,10); if(!isNaN(idx))o.splice(idx,1); }
      else if(k in o) delete o[k];
      return; }
    if(k==='[-]'){ if(Array.isArray(o)){ for(var a=o.length-1;a>=0;a--){ if(hasPath(o[a],path,i+1))o.splice(a,1); } } return; }
    if(k==='[]'||k==='*'){ if(Array.isArray(o)){ for(var b=0;b<o.length;b++)prunePath(o[b],path,i+1); }
      else { for(var key in o)prunePath(o[key],path,i+1); } return; }
    prunePath(o[k],path,i+1); }
  function makePruner(props){ var list=String(props).split(/\s+/).filter(Boolean);
    return function(o){ for(var i=0;i<list.length;i++){ try{prunePath(o,list[i].split('.'),0);}catch(e){} } return o; }; }
  function jsonPrune(props){ var prune=makePruner(props);
    try{ JSON.parse=new Proxy(JSON.parse,{apply:function(t,th,a){ var r=Reflect.apply(t,th,a);
      try{if(r&&typeof r==='object')prune(r);}catch(e){} return r; }}); }catch(e){}
    try{ Response.prototype.json=new Proxy(Response.prototype.json,{apply:function(t,th,a){
      return Reflect.apply(t,th,a).then(function(r){ try{if(r&&typeof r==='object')prune(r);}catch(e){} return r; }); }}); }catch(e){} }
  function rcv(th){ return (th===undefined||th===null)?W:th; }
  function urlMatcher(props){ if(!props)return function(){return true;};
    var s=String(props); var m=/url:\s*(\S+)/.exec(s); if(m)s=m[1];
    var re=toRe(s); return function(u){ try{return re.test(String(u));}catch(e){return false;} }; }
  function nazwany(args, klucz, odIndeksu){
    try{
      for(var i=odIndeksu||0;i<args.length-1;i++)
        if(String(args[i]).toLowerCase()===klucz.toLowerCase()) return args[i+1];
    }catch(e){}
    return undefined;
  }
  function replFetch(pattern,replacement,props){
    var re=toRe(pattern||'',true); var rep=(replacement===undefined?'':String(replacement)); var match=urlMatcher(props);
    if(rep==='$1'){}
    try{ if(typeof W.fetch!=='function')return;
      W.fetch=new Proxy(W.fetch,{apply:function(F,thisArg,args){ var url='';
        try{ url=(typeof args[0]==='string')?args[0]:(args[0]&&args[0].url)||''; }catch(e){}
        var p=Reflect.apply(F,rcv(thisArg),args);
        if(!match(url)||!pattern) return p;
        return p.then(function(resp){
          try{ var clone=resp.clone();
            return clone.text().then(function(t){
              var nt; try{ nt=t.replace(re,rep); }catch(e){ nt=t; }
              if(nt===t) return resp;
              var init={status:resp.status,statusText:resp.statusText,headers:resp.headers};
              var nr=new Response(nt,init);
              try{Object.defineProperty(nr,'url',{value:resp.url});}catch(e){}
              return nr;
            }).catch(function(){return resp;});
          }catch(e){ return resp; }
        });
      }});
    }catch(e){} }
  function replXhr(pattern,replacement,props){
    var re=toRe(pattern||'',true); var rep=(replacement===undefined?'':String(replacement)); var match=urlMatcher(props);
    try{
      var P=XMLHttpRequest.prototype;
      var dText=Object.getOwnPropertyDescriptor(P,'responseText');
      var dResp=Object.getOwnPropertyDescriptor(P,'response');
      P.open=new Proxy(P.open,{apply:function(O,xhr,a){
        var u=a[1];
        try{
          if(pattern&&match(u||'')){
            var wrap=function(desc,key){
              if(!desc||!desc.get)return null;
              return function(){ var v=desc.get.call(this);
                if(typeof v!=='string')return v;
                var c = this[key];
                if(c && c.src===v) return c.out;
                var out; try{ out = v.replace(re,rep); }catch(e){ return v; }
                try{ this[key] = {src:v,out:out}; }catch(e){}
                return out; };
            };
            var gT=wrap(dText,"__abRT"), gR=wrap(dResp,"__abRR");
            if(gT) Object.defineProperty(xhr,'responseText',{configurable:true,get:gT});
            if(gR) Object.defineProperty(xhr,'response',{configurable:true,get:gR});
          }
        }catch(e){}
        return Reflect.apply(O,xhr,a); }}); }catch(e){} }
  function jsonPruneFetch(props,a2,a3){
    var wz=nazwany(arguments,'propsToMatch',1);
    var prune=makePruner(props); var match=urlMatcher(wz!==undefined?wz:(a3||a2));
    try{ if(typeof W.fetch!=='function')return;
      W.fetch=new Proxy(W.fetch,{apply:function(F,thisArg,args){ var url='';
        try{ url=(typeof args[0]==='string')?args[0]:(args[0]&&args[0].url)||''; }catch(e){}
        var p=Reflect.apply(F,rcv(thisArg),args);
        if(!match(url)) return p;
        return p.then(function(resp){
          try{ var clone=resp.clone();
            return clone.text().then(function(t){
              var o; try{o=JSON.parse(t);}catch(e){return resp;}
              try{prune(o);}catch(e){return resp;}
              var nr=new Response(JSON.stringify(o),{status:resp.status,statusText:resp.statusText,headers:resp.headers});
              try{Object.defineProperty(nr,'url',{value:resp.url});}catch(e){}
              return nr;
            }).catch(function(){return resp;});
          }catch(e){return resp;} });
      }});
    }catch(e){} }
  function acs(chain,needle){ var parts=String(chain).split('.'); var re=needle?toRe(needle):null;
    function shouldAbort(){ try{ var s=document.currentScript; if(!s)return false;
      if(!re)return true; var txt=s.textContent||s.src||''; return re.test(txt); }catch(e){ return false; } }
    function ins(owner,i){ if(owner==null)return; var p=parts[i];
      if(i===parts.length-1){ try{ var orig=owner[p];
        Object.defineProperty(owner,p,{configurable:true,
          get:function(){ if(shouldAbort())throw new ReferenceError(p); return orig; },
          set:function(v){ orig=v; }});
      }catch(e){} return; }
      var o; try{o=owner[p];}catch(e){return;} if(o)ins(o,i+1); }
    ins(W,0); }
  function nowoif(needle){ var re=needle?toRe(needle):/.?/;
    try{ W.open=new Proxy(W.open,{apply:function(t,th,a){
      try{ if(re.test(String(a[0])))return null; }catch(e){}
      return Reflect.apply(t,rcv(th),a); }}); }catch(e){} }
  function jsonPruneXhr(props,a2,a3){
    var wz=nazwany(arguments,'propsToMatch',1);
    var prune = makePruner(props); var match = urlMatcher(wz!==undefined?wz:(a3||a2));
    try{
      var P = XMLHttpRequest.prototype;
      var dText = Object.getOwnPropertyDescriptor(P,'responseText');
      var dResp = Object.getOwnPropertyDescriptor(P,'response');
      P.open = new Proxy(P.open,{apply:function(O,xhr,a){
        var u=a[1];
        try{
          if(match(u||'')){
            var mk = function(desc,isText){
              if(!desc||!desc.get) return null;
              return function(){
                var v = desc.get.call(this);
                if(isText){
                  if(typeof v!=='string') return v;
                  if(this.__abPT && this.__abPT.src===v) return this.__abPT.out;
                  var o; try{ o=JSON.parse(v); }catch(e){ return v; }
                  try{ prune(o); }catch(e){ return v; }
                  var out = JSON.stringify(o);
                  try{ this.__abPT = {src:v,out:out}; }catch(e){}
                  return out;
                }
                if(v && typeof v==='object'){ try{ prune(v); }catch(e){} return v; }
                if(typeof v==='string'){
                  if(this.__abPR && this.__abPR.src===v) return this.__abPR.out;
                  var o2; try{ o2=JSON.parse(v); }catch(e){ return v; }
                  try{ prune(o2); }catch(e){ return v; }
                  var out2 = JSON.stringify(o2);
                  try{ this.__abPR = {src:v,out:out2}; }catch(e){}
                  return out2;
                }
                return v;
              };
            };
            var gT = mk(dText,true), gR = mk(dResp,false);
            if(gT) Object.defineProperty(xhr,'responseText',{configurable:true,get:gT});
            if(gR) Object.defineProperty(xhr,'response',{configurable:true,get:gR});
          }
        }catch(e){}
        return Reflect.apply(O,xhr,a); }}); }catch(e){} }
  function adjustSetTimeout(needle,delay,boost){ var re=needle?toRe(needle):/.?/;
    var d=parseInt(delay,10); var b=parseFloat(boost); if(isNaN(b)||b<=0)b=0.02;
    try{ W.setTimeout=new Proxy(W.setTimeout,{apply:function(t0,th,a){
      try{ var s=(typeof a[0]==='function')?a[0].toString():String(a[0]);
        if((isNaN(d)||a[1]===d)&&re.test(s)) a[1]=a[1]*b; }catch(e){}
      return Reflect.apply(t0,rcv(th),a); }}); }catch(e){} }
  function toRe(s,zostawG){ if(!s)return /.?/;
    if(s.length>1&&s.charAt(0)==='/'){ var k=s.lastIndexOf('/');
      if(k>0){ var tresc=s.slice(1,k), fl=s.slice(k+1);
        if(/^[gimsuy]*$/.test(fl)){
          try{ return new RegExp(tresc, zostawG?fl.replace(/[^gimsu]/g,''):fl.replace(/[^imsu]/g,'')); }catch(e){} } } }
    try{return new RegExp(s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'));}catch(e){return /.?/;} }
  function aopw(chain){ var parts=String(chain).split('.');
    function ins(owner,i){ if(owner==null)return; var p=parts[i];
      if(i===parts.length-1){ try{Object.defineProperty(owner,p,{configurable:false,get:function(){return undefined;},set:function(){throw new ReferenceError(p);}});}catch(e){} return; }
      var o; try{o=owner[p];}catch(e){return;} if(o)ins(o,i+1); }
    ins(W,0); }
  function delPasuje(d,neg,raw){ if(isNaN(d))return true; var v=Number(raw); if(!isFinite(v))v=0; return neg?(v!==d):(v===d); }
  function delSpec(delay){ var s=String(delay==null?'':delay).trim(); var neg=false;
    if(s.charAt(0)==='!'){ neg=true; s=s.slice(1); } return {d:parseInt(s,10),neg:neg}; }
  function nostif(needle,delay){ var re=toRe(needle); var q=delSpec(delay);
    try{ W.setTimeout=new Proxy(W.setTimeout,{apply:function(t,th,a){
      try{ var s=(typeof a[0]==='function')?a[0].toString():String(a[0]);
           if(re.test(s)&&delPasuje(q.d,q.neg,a[1]))return 0; }catch(e){}
      return Reflect.apply(t,rcv(th),a); }}); }catch(e){} }
  function nosiif(needle,delay){ var re=toRe(needle); var q=delSpec(delay);
    try{ W.setInterval=new Proxy(W.setInterval,{apply:function(t,th,a){
      try{ var s=(typeof a[0]==='function')?a[0].toString():String(a[0]);
           if(re.test(s)&&delPasuje(q.d,q.neg,a[1]))return 0; }catch(e){}
      return Reflect.apply(t,rcv(th),a); }}); }catch(e){} }
  function removeCookie(needle){ try{ var re=toRe(needle); var cs=document.cookie.split(';');
    for(var i=0;i<cs.length;i++){ var n=cs[i].split('=')[0].trim(); if(!needle||re.test(n)){ var ps=location.hostname.split('.');
      document.cookie=n+'=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
      for(var k=0;k<ps.length-1;k++){ var d='.'+ps.slice(k).join('.'); document.cookie=n+'=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; domain='+d; } } } }catch(e){} }
  var NOXHR = null;
  function noXhrIf(props){
    var m=/method:(\w+)/i.exec(String(props||''));
    var pat=String(props||'').replace(/\s*method:\w+\s*/i,'').trim();
    var rule={ match:urlMatcher(pat||props), method:m?m[1].toUpperCase():null };
    if(NOXHR){ NOXHR.push(rule); return; }
    NOXHR=[rule];
    try{
      XMLHttpRequest.prototype.open=new Proxy(XMLHttpRequest.prototype.open,{apply:function(t,th,a){
        try{
          var url=String(a[1]||''), meth=String(a[0]||'').toUpperCase(), hit=false;
          for(var i=0;i<NOXHR.length;i++){
            var r=NOXHR[i];
            if(r.match(url) && (!r.method || r.method===meth)){ hit=true; break; }
          }
          th.__abNoXhr=hit;
        }catch(e){}
        return Reflect.apply(t,th,a); }});
      XMLHttpRequest.prototype.send=new Proxy(XMLHttpRequest.prototype.send,{apply:function(t,th,a){
        if(!th.__abNoXhr) return Reflect.apply(t,th,a);
        try{
          Object.defineProperty(th,'readyState',{value:4,configurable:true});
          Object.defineProperty(th,'status',{value:200,configurable:true});
          Object.defineProperty(th,'responseText',{value:'',configurable:true});
          Object.defineProperty(th,'response',{value:'',configurable:true});
        }catch(e){}
        setTimeout(function(){ try{
          if(typeof th.onreadystatechange==='function') th.onreadystatechange();
          th.dispatchEvent(new Event('readystatechange'));
          if(typeof th.onload==='function') th.onload();
          th.dispatchEvent(new Event('load'));
          th.dispatchEvent(new Event('loadend'));
        }catch(e){} },0);
      }});
    }catch(e){}
  }
  function preventDomBypass(target,needle){
    var t=String(target||'Node.prototype.appendChild');
    var parts=t.split('.'); var meth=parts.pop();
    var owner=W; for(var i=0;i<parts.length;i++){ try{ owner=owner[parts[i]]; }catch(e){ owner=null; } if(!owner)return; }
    try{
      owner[meth]=new Proxy(owner[meth],{apply:function(f,th,a){
        var node=a[0];
        var r=Reflect.apply(f,th,a);
        try{
          if(node && node.tagName==='IFRAME' && node.contentWindow){
            var cw=node.contentWindow;
            var props=String(needle||'').split(/[|\s]+/).filter(Boolean);
            for(var j=0;j<props.length;j++){
              var chain=props[j].split('.');
              var srcO=W, dstO=cw, ok=true;
              for(var k=0;k<chain.length-1;k++){ srcO=srcO&&srcO[chain[k]]; dstO=dstO&&dstO[chain[k]]; if(!srcO||!dstO){ok=false;break;} }
              if(ok){ try{ dstO[chain[chain.length-1]] = srcO[chain[chain.length-1]]; }catch(e){} }
            }
          }
        }catch(e){}
        return r; }});
    }catch(e){}
  }
  var NOFETCH=null;
  function preventFetch(props,resp){
    var rule={ match:urlMatcher(props), resp:String(resp||'') };
    if(NOFETCH){ NOFETCH.push(rule); return; }
    NOFETCH=[rule];
    try{
      if(typeof W.fetch!=='function') return;
      W.fetch=new Proxy(W.fetch,{apply:function(F,th,a){
        var url='';
        try{ url=(typeof a[0]==='string')?a[0]:(a[0]&&a[0].url)||''; }catch(e){}
        for(var i=0;i<NOFETCH.length;i++){
          var r=NOFETCH[i];
          if(!r.match(url)) continue;
          var body = r.resp==='emptyObj' ? '{}' : (r.resp==='emptyArr' ? '[]' : r.resp);
          try{
            var ct = (body.charAt(0)==='{'||body.charAt(0)==='[') ? 'application/json' : 'text/plain';
            var res=new Response(body,{status:200,statusText:'OK',headers:{'Content-Type':ct}});
            try{ Object.defineProperty(res,'url',{value:url}); }catch(e){}
            return Promise.resolve(res);
          }catch(e){ return Promise.resolve(new Response('')); }
        }
        return Reflect.apply(F,rcv(th),a); }});
    }catch(e){}
  }
  var AELD=null;
  function aeld(type,needle){
    var rule={ t: type?toRe(type):/.?/, h: needle?toRe(needle):/.?/ };
    if(AELD){ AELD.push(rule); return; }
    AELD=[rule];
    try{
      EventTarget.prototype.addEventListener=new Proxy(EventTarget.prototype.addEventListener,{
        apply:function(f,th,a){
          try{
            var t=String(a[0]||'');
            var h=(typeof a[1]==='function')?a[1].toString():String((a[1]&&a[1].handleEvent)||a[1]||'');
            for(var i=0;i<AELD.length;i++)
              if(AELD[i].t.test(t) && AELD[i].h.test(h)) return undefined;
          }catch(e){}
          return Reflect.apply(f,th,a); }});
    }catch(e){}
  }
  var GUARD=null;
  function storageGuard(){
    if(GUARD) return GUARD;
    GUARD={ local:Object.create(null), session:Object.create(null) };
    try{
      Storage.prototype.setItem=new Proxy(Storage.prototype.setItem,{apply:function(f,th,a){
        try{
          var g = (th===W.localStorage) ? GUARD.local
                : (th===W.sessionStorage) ? GUARD.session : null;
          var k = String(a[0]);
          if(g && Object.prototype.hasOwnProperty.call(g,k))
            return Reflect.apply(f,th,[k,g[k]]);
        }catch(e){}
        return Reflect.apply(f,th,a); }});
    }catch(e){}
    return GUARD;
  }
  function setStorageItem(store,which,key,value){
    try{
      var v=String(value);
      var map={ 'undefined':null,'$remove$':null,
                'false':'false','true':'true','on':'on','off':'off','yes':'yes','no':'no',
                'accept':'accept','accepted':'accepted','reject':'reject','rejected':'rejected',
                'allowed':'allowed','denied':'denied','forbidden':'forbidden',
                'emptyArr':'[]','emptyObj':'{}' };
      var out;
      if(Object.prototype.hasOwnProperty.call(map,v)) out=map[v];
      else if(/^-?\d+$/.test(v) && Math.abs(+v)<=32767) out=v;
      else if(/^\{[\s\S]*\}$/.test(v) || /^\[[\s\S]*\]$/.test(v)) out=v;
      else return;
      var g=storageGuard();
      var slot = which==='session' ? g.session : g.local;
      if(out===null){ delete slot[key]; store.removeItem(key); return; }
      slot[key]=out;
      store.setItem(key,out);
    }catch(e){}
  }
  function setLocalStorageItem(k,v){ try{ setStorageItem(W.localStorage,'local',k,v); }catch(e){} }
  function setSessionStorageItem(k,v){ try{ setStorageItem(W.sessionStorage,'session',k,v); }catch(e){} }
  function trustedSetCookie(name,value,ttl,path){
    try{
      var exp='; expires='+new Date(Date.now()+31536000000).toUTCString();
      if(ttl){
        var m=/^(\d+)([smhd]?)$/.exec(String(ttl));
        if(m){
          var mult={ '':1000,'s':1000,'m':60000,'h':3600000,'d':86400000 }[m[2]];
          exp='; expires='+new Date(Date.now()+(+m[1])*mult).toUTCString();
        } else if(String(ttl)==='session') exp='';
      }
      document.cookie=encodeURIComponent(name)+'='+encodeURIComponent(String(value))+
                      '; path='+(path||'/')+exp;
    }catch(e){}
  }
  function trustedClickElement(selectors,extra,delay){
    var sels=String(selectors||'').split(/\s*,\s*/).filter(Boolean);
    if(sels.length===0) return;
    var wait=parseInt(delay,10); if(isNaN(wait)||wait<0) wait=0;
    var done={}, tries=0, timer=null;
    function run(){
      tries++;
      for(var i=0;i<sels.length;i++){
        if(done[i]) continue;
        var el=null;
        try{ el=document.querySelector(sels[i]); }catch(e){ done[i]=1; continue; }
        if(!el) continue;
        try{ el.click(); done[i]=1; }catch(e){}
      }
      if(tries>40 && timer) clearInterval(timer);
    }
    setTimeout(function(){ run(); timer=setInterval(run,250); }, wait);
  }
  function adjustSetInterval(needle,delay,boost){
    var re=needle?toRe(needle):/.?/;
    var d=parseInt(delay,10); var b=parseFloat(boost); if(isNaN(b)||b<=0)b=0.05;
    try{ W.setInterval=new Proxy(W.setInterval,{apply:function(t0,th,a){
      try{ var str=(typeof a[0]==='function')?a[0].toString():String(a[0]);
        if((isNaN(d)||a[1]===d)&&re.test(str)) a[1]=a[1]*b; }catch(e){}
      return Reflect.apply(t0,rcv(th),a); }}); }catch(e){} }
  function setCookie(name,value,path){
    try{
      var v=String(value);
      var ok=/^(true|false|yes|no|y|n|ok|on|off|accept|accepted|reject|rejected|allow|deny|null|undefined|0|1|[0-9]{1,10})$/i;
      if(!ok.test(v)) return;
      var c=encodeURIComponent(name)+'='+encodeURIComponent(v)+'; path='+(path||'/')+
            '; expires='+new Date(Date.now()+31536000000).toUTCString();
      document.cookie=c;
    }catch(e){}
  }
  function preventElementSrcLoading(tag,needle){
    var t=String(tag||'').toLowerCase(); if(!t) return;
    var re=toRe(needle);
    var proto = t==='script'?HTMLScriptElement.prototype
              : t==='iframe'?HTMLIFrameElement.prototype
              : t==='img'?HTMLImageElement.prototype
              : t==='link'?HTMLLinkElement.prototype : null;
    if(!proto) return;
    var attr = t==='link' ? 'href' : 'src';
    try{
      var d=Object.getOwnPropertyDescriptor(proto,attr);
      if(!d||!d.set) return;
      Object.defineProperty(proto,attr,{ configurable:true, enumerable:d.enumerable,
        get:function(){ return this.__abSrc!==undefined ? this.__abSrc : d.get.call(this); },
        set:function(v){
          if(re.test(String(v))){
            this.__abSrc=v;
            var self=this;
            setTimeout(function(){ try{ self.dispatchEvent(new Event('load')); }catch(e){} },0);
            return;
          }
          d.set.call(this,v);
        }});
    }catch(e){}
    try{
      var sa=Element.prototype.setAttribute;
      Element.prototype.setAttribute=new Proxy(sa,{apply:function(f,th,a){
        try{
          if(th && String(th.tagName||'').toLowerCase()===t &&
             String(a[0]||'').toLowerCase()===attr && re.test(String(a[1]))) return;
        }catch(e){}
        return Reflect.apply(f,th,a); }});
    }catch(e){}
  }
  function nodeTextWorker(sel,pat,rep,extra){
    var tag=String(sel||''); var re=pat?toRe(pat,true):null;
    var cond=extra&&extra.condition?toRe(extra.condition):null;
    if(!tag||!re) return;
    var STRUCTURAL={HTML:1,HEAD:1,BODY:1,FRAMESET:1};
    function applies(el){ try{
      if(!el||el.nodeType!==1) return false;
      if(STRUCTURAL[String(el.tagName||'').toUpperCase()]) return false;
      return !el.matches || el.matches(tag);
    }catch(e){ return false; } }
    function hit(el){ try{
      if(!applies(el))return;
      if(cond&&!cond.test(el.textContent||''))return;
      var t=el.textContent; if(t==null)return;
      var out=t.replace(re, rep===undefined?'':String(rep));
      if(out!==t) el.textContent=out;
    }catch(e){} }
    function sweep(root){ try{
      var els=(root||document).querySelectorAll(tag);
      for(var i=0;i<els.length;i++) hit(els[i]);
    }catch(e){} }
    W.__abObs(function(added){
      if(!added){ sweep(document); return; }
      for(var i=0;i<added.length;i++){
        var a=added[i];
        try{ if(a.matches&&a.matches(tag)) hit(a); }catch(e){}
        sweep(a);
      }
    });
  }
  function rpnt(sel,pat,rep){
    var extra={}; var c=nazwany(arguments,'condition',3); if(c!==undefined)extra.condition=c;
    nodeTextWorker(sel,pat,rep===undefined?'':rep,extra);
  }
  function rmntReal(sel,pat){
    var extra={}; var c=nazwany(arguments,'condition',2); if(c!==undefined)extra.condition=c;
    nodeTextWorker(sel,pat,'',extra);
  }
  function stackHas(re){
    try{ var st=new Error().stack||''; return re.test(st); }catch(e){ return false; }
  }
  function aost(chain,needle){
    var parts=String(chain).split('.'); var re=needle?toRe(needle):/.?/;
    function ins(owner,i){ if(owner==null)return; var p=parts[i];
      if(i===parts.length-1){
        var orig; try{ orig=owner[p]; }catch(e){ orig=undefined; }
        try{ Object.defineProperty(owner,p,{configurable:true,
          get:function(){ if(stackHas(re)) throw new ReferenceError(p); return orig; },
          set:function(v){ orig=v; }}); }catch(e){}
        return; }
      var o; try{o=owner[p];}catch(e){return;} if(o)ins(o,i+1); }
    ins(W,0);
  }
  function hrefSanitizer(sel,attr){
    var selector=String(sel||'a[href]'); var source=String(attr||'?');
    function clean(a){ try{
      var raw=a.getAttribute('href'); if(!raw)return;
      var out=null;
      if(source==='text'){ out=(a.textContent||'').trim(); }
      else if(source.charAt(0)==='?'){
        var key=source.slice(1);
        var u=new URL(raw, document.baseURI);
        if(key) out=u.searchParams.get(key);
        else { u.search=''; out=u.href; }
      } else if(source.charAt(0)==='['){ out=a.getAttribute(source.slice(1,-1)); }
      if(!out)return;
      if(/^https?:/i.test(out)||out.charAt(0)==='/') a.setAttribute('href',out);
    }catch(e){} }
    function sweep(){ try{ var els=document.querySelectorAll(selector);
      for(var i=0;i<els.length;i++) clean(els[i]); }catch(e){} }
    W.__abObs(sweep);
  }
  function preventEvalIf(needle){
    var re=needle?toRe(needle):/.?/;
    try{ W.eval=new Proxy(W.eval,{apply:function(t,th,a){
      try{ if(re.test(String(a[0])))return undefined; }catch(e){}
      return Reflect.apply(t,rcv(th),a); }}); }catch(e){}
    try{ W.Function=new Proxy(W.Function,{construct:function(T,a){
      try{ if(re.test(a.join(' ')))return function(){}; }catch(e){}
      return Reflect.construct(T,a); }}); }catch(e){}
  }
  function resolveMethod(path){
    var parts=String(path).split('.'); var owner=W;
    for(var i=0;i<parts.length-1;i++){
      try{ owner=owner[parts[i]]; }catch(e){ return null; }
      if(owner==null) return null;
    }
    var name=parts[parts.length-1];
    var fn; try{ fn=owner[name]; }catch(e){ return null; }
    if(typeof fn!=='function') return null;
    return {owner:owner,name:name,fn:fn};
  }
  function suppressNativeMethod(path,argPattern,how,stackNeedle){
    var m=resolveMethod(path); if(!m)return;
    var re=argPattern?toRe(argPattern):/.?/;
    var mode=String(how||'abort');
    var stackRe=stackNeedle?toRe(stackNeedle):null;
    try{
      m.owner[m.name]=new Proxy(m.fn,{apply:function(t,th,a){
        var matched=false;
        try{ for(var i=0;i<a.length;i++){ if(re.test(String(a[i]))){ matched=true; break; } } }catch(e){}
        if(matched&&stackRe&&!stackHas(stackRe)) matched=false;
        if(matched){
          if(mode==='throw') throw new ReferenceError(m.name);
          return undefined;
        }
        return Reflect.apply(t,rcv(th),a); }});
    }catch(e){}
  }
  function pruneInboundObject(path,argPos,props){
    var m=resolveMethod(path); if(!m)return;
    var idx=parseInt(argPos,10); if(isNaN(idx))idx=0;
    var prune=makePruner(props||'');
    try{
      m.owner[m.name]=new Proxy(m.fn,{apply:function(t,th,a){
        try{ var o=a[idx]; if(o&&typeof o==='object') prune(o); }catch(e){}
        return Reflect.apply(t,rcv(th),a); }});
    }catch(e){}
  }
  function replaceArgument(path,argPos,value){
    var m=resolveMethod(path); if(!m)return;
    var idx=parseInt(argPos,10); if(isNaN(idx))idx=0;
    var want=pv(String(value));
    var cond=nazwany(arguments,'condition',3);
    var re=cond!==undefined?toRe(cond):null;
    try{
      m.owner[m.name]=new Proxy(m.fn,{apply:function(t,th,a){
        try{ if(!re||re.test(String(a[idx]))) a[idx]=want; }catch(e){}
        return Reflect.apply(t,rcv(th),a); }});
    }catch(e){}
  }
  function setAttr(sel,attr,value){
    var v=value===undefined?'':String(value);
    function run(){ try{ var els=document.querySelectorAll(sel);
      for(var i=0;i<els.length;i++){ try{ els[i].setAttribute(attr,v); }catch(e){} } }catch(e){} }
    W.__abObs(run);
  }
  function noAbDetect(){
    try{ W.FuckAdBlock=W.BlockAdBlock=function(){}; }catch(e){}
    var names=['fuckAdBlock','blockAdBlock','sniffAdBlock','adBlockDetected','adsBlocked'];
    function shim(){ return {
      check:function(){return false;},clearEvent:function(){return this;},
      on:function(){return this;},onDetected:function(){return this;},
      onNotDetected:function(cb){ try{ if(typeof cb==='function') setTimeout(cb,0); }catch(e){} return this; },
      setOption:function(){return this;},emitEvent:function(){return this;} }; }
    for(var i=0;i<names.length;i++){
      try{ Object.defineProperty(W,names[i],{configurable:true,get:shim,set:function(){}}); }catch(e){}
    }
  }
  function popadsDummy(){
    try{ Object.defineProperty(W,'PopAds',{value:{},writable:false,configurable:false}); }catch(e){}
    try{ Object.defineProperty(W,'popns',{value:{},writable:false,configurable:false}); }catch(e){}
  }
  function refreshDefuser(){
    function strip(){ try{
      var ms=document.querySelectorAll('meta[http-equiv="refresh" i]');
      for(var i=0;i<ms.length;i++) ms[i].parentNode.removeChild(ms[i]);
    }catch(e){} }
    W.__abObs(strip);
  }
  function splitTop(src,from){
    var depth=0,q=0,i=from;
    for(;i<src.length;i++){
      var c=src.charAt(i);
      if(q){ if(c==='\\'){i++;continue;} if(c===q)q=0; continue; }
      if(c==='"'||c==="'"){ q=c; continue; }
      if(c==='['||c==='{'||c==='(')depth++;
      else if(c===']'||c==='}'||c===')')depth--;
      else if(depth===0&&(c==='='||c==='+')){
        if(c==='+'&&src.charAt(i+1)!=='=')continue;
        return i;
      }
    }
    return -1;
  }
  function matchBracket(src,start){
    var depth=0,q=0;
    for(var i=start;i<src.length;i++){
      var c=src.charAt(i);
      if(q){ if(c==='\\'){i++;continue;} if(c===q)q=0; continue; }
      if(c==='"'||c==="'"){ q=c; continue; }
      if(c==='[')depth++;
      else if(c===']'){ depth--; if(depth===0)return i; }
    }
    return -1;
  }
  function parseCond(body){
    var neg=false,i=0;
    if(body.charAt(i)==='?')i++;
    if(body.charAt(i)==='!'){ neg=true; i++; }
    var rest=body.slice(i);
    var deep=false;
    if(rest.slice(0,2)==='..'){ deep=true; rest=rest.slice(2); }
    else if(rest.charAt(0)==='.'){ rest=rest.slice(1); }
    var op=null,val=null,cut=-1;
    var ops=['==','*=','^=','=/','='];
    for(var k=0;k<ops.length;k++){
      var at=rest.indexOf(ops[k]);
      if(at>=0&&(cut<0||at<cut)){ cut=at; op=ops[k]; }
    }
    if(cut>=0){
      val=rest.slice(cut+(op==='=/'?1:op.length));
      rest=rest.slice(0,cut);
      if(op==='=/'){ op='=~'; }
      else { val=unquote(val); }
      if(op==='=~'){ val=toRe(val); }
    }
    if(!rest)return null;
    return {neg:neg,deep:deep,path:rest.split('.').filter(Boolean),op:op,val:val};
  }
  function unquote(v){
    v=String(v).trim();
    if(v.length>1&&(v.charAt(0)==='"'||v.charAt(0)==="'")&&v.charAt(v.length-1)===v.charAt(0))
      return v.slice(1,-1);
    return v;
  }
  function walk(node,path,i,out,deep){
    if(node==null||typeof node!=='object')return;
    if(i>=path.length){ out.push(node); return; }
    var key=path[i];
    if(deep){
      if(Object.prototype.hasOwnProperty.call(node,key)) walk(node[key],path,i+1,out,false);
      for(var k in node){ try{ if(node[k]&&typeof node[k]==='object') walk(node[k],path,i,out,true); }catch(e){} }
      return;
    }
    if(Array.isArray(node)){ for(var j=0;j<node.length;j++) walk(node[j],path,i,out,false); return; }
    if(!Object.prototype.hasOwnProperty.call(node,key))return;
    walk(node[key],path,i+1,out,false);
  }
  function resolvePath(root,path,deep){
    var out=[]; walk(root,path,0,out,!!deep); return out;
  }
  function condHolds(root,c){
    if(!c)return true;
    var parent=c.path.slice(0,-1), last=c.path[c.path.length-1];
    var owners=resolvePath(root,parent,c.deep);
    var found=false;
    for(var i=0;i<owners.length;i++){
      var o=owners[i];
      if(o==null||typeof o!=='object')continue;
      if(!Object.prototype.hasOwnProperty.call(o,last))continue;
      var v=o[last];
      if(c.op===null){ found=true; break; }
      var sv=String(v);
      if(c.op==='=='&&sv===c.val){ found=true; break; }
      if(c.op==='*='&&sv.indexOf(c.val)>=0){ found=true; break; }
      if(c.op==='^='&&sv.lastIndexOf(c.val,0)===0){ found=true; break; }
      if(c.op==='=~'&&c.val.test(sv)){ found=true; break; }
    }
    return c.neg ? !found : found;
  }
  function parseEditExpr(expr){
    var src=String(expr).trim();
    var guards=[],i=0;
    while(src.charAt(i)==='['){
      var end=matchBracket(src,i); if(end<0)return null;
      var inner=src.slice(i+1,end);
      if(inner.charAt(0)!=='?')break;
      var g=parseCond(inner); if(!g)return null;
      guards.push(g); i=end+1;
    }
    var rest=src.slice(i);
    var opAt=splitTop(rest,0);
    if(opAt<0)return null;
    var merge=rest.charAt(opAt)==='+';
    var pathPart=rest.slice(0,opAt);
    var valuePart=rest.slice(opAt+(merge?2:1)).trim();

    var filters=[],fi;
    while((fi=pathPart.indexOf('['))>=0){
      var fe=matchBracket(pathPart,fi); if(fe<0)return null;
      var fc=parseCond(pathPart.slice(fi+1,fe)); if(fc)filters.push(fc);
      pathPart=pathPart.slice(0,fi)+pathPart.slice(fe+1);
    }
    var deep=false;
    if(pathPart.slice(0,2)==='..'){ deep=true; pathPart=pathPart.slice(2); }
    else if(pathPart.charAt(0)==='.'){ pathPart=pathPart.slice(1); }
    var path=pathPart.split('.').filter(Boolean);
    if(path.length===0)return null;

    var value;
    if(merge){
      try{ value={kind:'merge',data:JSON.parse(valuePart)}; }catch(e){ return null; }
    } else if(valuePart.slice(0,5)==='repl('){
      var cfgText=valuePart.slice(5,valuePart.lastIndexOf(')'));
      var cfg; try{ cfg=JSON.parse(cfgText); }catch(e){ return null; }
      value={kind:'repl',re:toRe(cfg.regex||'',true),rep:cfg.replacement===undefined?'':cfg.replacement};
    } else {
      value={kind:'set',text:unquote(valuePart)};
    }
    return {guards:guards,filters:filters,path:path,deep:deep,value:value};
  }
  function expandTemplate(text){
    return String(text).replace(/\$\{now\}/g,function(){ return String(Date.now()); });
  }
  function applyEdit(root,plan){
    for(var g=0;g<plan.guards.length;g++) if(!condHolds(root,plan.guards[g])) return;
    var parent=plan.path.slice(0,-1), last=plan.path[plan.path.length-1];
    var owners=resolvePath(root,parent,plan.deep);
    for(var i=0;i<owners.length;i++){
      var o=owners[i];
      if(o==null||typeof o!=='object')continue;
      var target=null; try{ target=o[last]; }catch(e){}
      var ok=true;
      for(var f=0;f<plan.filters.length;f++){
        if(target==null||typeof target!=='object'||!condHolds(target,plan.filters[f])){ ok=false; break; }
      }
      if(!ok)continue;
      try{
        if(plan.value.kind==='merge'){
          var tgt=o[last];
          if(tgt==null||typeof tgt!=='object'){ tgt={}; o[last]=tgt; }
          for(var k in plan.value.data) tgt[k]=plan.value.data[k];
        } else if(plan.value.kind==='repl'){
          var cur=o[last]; if(typeof cur!=='string')continue;
          o[last]=cur.replace(plan.value.re,plan.value.rep);
        } else {
          o[last]=expandTemplate(plan.value.text);
        }
      }catch(e){}
    }
  }
  function editInboundObject(methodPath,argPos,expr){
    var m=resolveMethod(methodPath); if(!m)return;
    var idx=parseInt(argPos,10); if(isNaN(idx))idx=0;
    var plan=parseEditExpr(expr); if(!plan)return;
    try{
      m.owner[m.name]=new Proxy(m.fn,{apply:function(t,th,a){
        try{ var o=a[idx]; if(o&&typeof o==='object') applyEdit(o,plan); }catch(e){}
        return Reflect.apply(t,rcv(th),a); }});
    }catch(e){}
  }
  function googleIma3(){ __AB_IMA__ }
  var reg={ 'set-constant':setConstant,'set':setConstant,'abort-on-property-read':aopr,'aopr':aopr,
    'abort-on-property-write':aopw,'aopw':aopw,
    'abort-current-inline-script':acs,'acis':acs,'abort-current-script':acs,'acs':acs,
    'remove-attr':removeAttr,'ra':removeAttr,'remove-class':removeClass,'rc':removeClass,
    'json-prune':jsonPrune,'jsonprune':jsonPrune,'noeval':function(){W.eval=function(){};},
    'no-setTimeout-if':nostif,'nostif':nostif,'setTimeout-defuser':nostif,'std.js':nostif,
    'no-setInterval-if':nosiif,'nosiif':nosiif,'setInterval-defuser':nosiif,
    'remove-cookie':removeCookie,'cookie-remover':removeCookie,'remove-cookie.js':removeCookie,
    'trusted-replace-fetch-response':replFetch,'replace-fetch-response':replFetch,
    'trusted-replace-xhr-response':replXhr,'replace-xhr-response':replXhr,
    'json-prune-fetch-response':jsonPruneFetch,'json-prune-xhr-response':jsonPruneXhr,
    'no-window-open-if':nowoif,'nowoif':nowoif,'window.open-defuser':nowoif,
    'remove-node-text':rmntReal,'rmnt':rmntReal,
    'replace-node-text':rpnt,'rpnt':rpnt,'trusted-replace-node-text':rpnt,'trusted-rpnt':rpnt,
    'abort-on-stack-trace':aost,'aost':aost,
    'href-sanitizer':hrefSanitizer,
    'prevent-eval-if':preventEvalIf,'noeval-if':preventEvalIf,
    'trusted-suppress-native-method':suppressNativeMethod,
    'trusted-prune-inbound-object':pruneInboundObject,
    'trusted-edit-inbound-object':editInboundObject,
    'trusted-replace-argument':replaceArgument,
    'set-attr':setAttr,'trusted-set-attr':setAttr,
    'trusted-set':setConstant,'trusted-set-constant':setConstant,
    'trusted-rpfr':replFetch,
    'nobab':noAbDetect,'nofab':noAbDetect,'prevent-bab':noAbDetect,'bab-defuser':noAbDetect,
    'popads-dummy':popadsDummy,'popads.net':popadsDummy,
    'refresh-defuser':refreshDefuser,
    'adjust-setTimeout':adjustSetTimeout,'nano-setTimeout-booster':adjustSetTimeout,'nano-stb':adjustSetTimeout,
    'adjust-setInterval':adjustSetInterval,'nano-setInterval-booster':adjustSetInterval,'nano-sib':adjustSetInterval,
    'no-xhr-if':noXhrIf,'noxhrif':noXhrIf,'prevent-xhr':noXhrIf,
    'prevent-fetch':preventFetch,'no-fetch-if':preventFetch,'nofif':preventFetch,
    'addEventListener-defuser':aeld,'aeld':aeld,'prevent-addEventListener':aeld,
    'set-local-storage-item':setLocalStorageItem,'trusted-set-local-storage-item':setLocalStorageItem,
    'set-session-storage-item':setSessionStorageItem,'trusted-set-session-storage-item':setSessionStorageItem,
    'trusted-set-cookie':trustedSetCookie,'trusted-set-cookie-reload':trustedSetCookie,
    'trusted-click-element':trustedClickElement,
    'prevent-setTimeout':nostif,'prevent-setInterval':nosiif,
    'prevent-window-open':nowoif,
    'set-cookie':setCookie,'set-cookie-reload':setCookie,
    'prevent-element-src-loading':preventElementSrcLoading,
    'google-ima3':googleIma3,'google-ima':googleIma3,
    'trusted-prevent-dom-bypass':preventDomBypass,'prevent-dom-bypass':preventDomBypass,
    'nowebrtc':function(){},'prevent-clipboard-write':function(){} };
  W.__abDone=[]; W.__abUnknown=[]; W.__abFailed=[];
  W.__abRun=function(name,args){
    var key=String(name).replace(/\.js$/,'');
    var bare=key.replace(/^(?:ubo|abp)-/,'');
    var f=reg[name]||reg[key]||reg[bare];
    if(!f){ try{W.__abUnknown.push(key);}catch(e){} return; }
    try{ f.apply(null,args||[]); try{W.__abDone.push(key);}catch(e){} }
    catch(err){ try{W.__abFailed.push(key+': '+err.message);}catch(e){} }
  };
})();
""";

    private const string Generic ="""
(function(){
  if(window.__abGen) return; window.__abGen=1;
  try {
    Object.defineProperty(window,'canRunAds',{get:function(){return true;},set:function(){},configurable:true});
    window.canShowAds=true; window.isAdBlockActive=false; window.adblockDetected=false; window.adBlockDetected=false;
    window.adsbygoogle=window.adsbygoogle||[]; try{window.adsbygoogle.loaded=true;}catch(e){}
    function FakeAB(){} FakeAB.prototype={on:function(){return this;},onDetected:function(){return this;},
      onNotDetected:function(cb){if(typeof cb==='function'){try{setTimeout(cb,0);}catch(e){}}return this;},
      check:function(){return this;},setOption:function(){return this;},emitEvent:function(){return this;},clearEvent:function(){return this;}};
    window.FuckAdBlock=window.BlockAdBlock=FakeAB; window.fuckAdBlock=window.blockAdBlock=new FakeAB();
    window.detectAdBlock=function(){return false;}; window.adblock=false;
  } catch(e){}
  try{
    var SLOWA=/(ad\s?-?block|adblokad|blokowani[ae] reklam|blokujesz reklamy|wy[lł][aą]cz.{0,20}(bloker|adblock)|disable.{0,20}ad\s?-?block|allow\s?list|zezw[oó]l na reklamy)/i;
    function widoczny(el){
      try{ var r=el.getBoundingClientRect(); var st=getComputedStyle(el);
        return r.width>200 && r.height>80 && st.display!=='none' && st.visibility!=='hidden' &&
               parseFloat(st.opacity||'1')>0.1; }catch(e){ return false; }
    }
    function selektor(el){
      try{
        if(el.id && /^[A-Za-z][\w-]*$/.test(el.id)) return '#'+el.id;
        var kl=(el.className&&typeof el.className==='string')?el.className.trim().split(/\s+/):[];
        kl=kl.filter(function(c){ return /^[A-Za-z][\w-]{2,}$/.test(c); }).slice(0,2);
        if(kl.length) return el.tagName.toLowerCase()+'.'+kl.join('.');
        return el.tagName.toLowerCase();
      }catch(e){ return ''; }
    }
    function szukaj(){
      try{
        if(sessionStorage.getItem('__abZgloszono')) return true;
        var kand=document.querySelectorAll('div,section,aside,dialog,tp-yt-paper-dialog');
        for(var i=0;i<kand.length && i<3000;i++){
          var el=kand[i];
          var st=getComputedStyle(el);
          var nakladka = st.position==='fixed' || st.position==='absolute' ||
                         el.tagName==='DIALOG' || el.getAttribute('role')==='dialog';
          if(!nakladka) continue;
          if(!widoczny(el)) continue;
          var t=(el.innerText||'').slice(0,600);
          if(t.length<20 || !SLOWA.test(t)) continue;
          var top=el;
          while(top.parentElement && top.parentElement!==document.body &&
                SLOWA.test((top.parentElement.innerText||'').slice(0,600))) top=top.parentElement;
          var sel=selektor(top);
          try{ sessionStorage.setItem('__abZgloszono','1'); }catch(e){}
          var u='https://report.adblocker.invalid/anti?host='+encodeURIComponent(location.hostname)+
                '&page='+encodeURIComponent(location.href.slice(0,300))+
                '&sel='+encodeURIComponent(sel)+
                '&txt='+encodeURIComponent(t.replace(/\s+/g,' ').slice(0,200));
          try{ (new Image()).src=u; }catch(e){}
          return true;
        }
      }catch(e){}
      return false;
    }
    var prob=0;
    var tm=setInterval(function(){ if(++prob>8 || szukaj()) clearInterval(tm); }, 1200);
    if(document.readyState!=='loading') setTimeout(szukaj,1500);
  }catch(e){}
  var SP=['sponsored','sponsorowane','gesponsert','commandité','patrocinado','sponsorisé','реклама','广告'];
  function hide(el){
    if(!el) return;
    var S=window.__abStyle;
    if(S){ if(S.marked(el)) return; if(S.apply(el,'display:none!important')) return; }
    if(el.style) el.style.setProperty('display','none','important');
  }
  function txt(el){ try{ var t='',w=document.createTreeWalker(el,NodeFilter.SHOW_TEXT,null),n,i=0;
    while((n=w.nextNode())&&i++<300){ var s=n.parentElement; if(!s)continue; var st=getComputedStyle(s);
      if(st&&(st.display==='none'||st.visibility==='hidden'))continue; t+=n.textContent; } return t.toLowerCase(); }
    catch(e){ return (el.textContent||'').toLowerCase(); } }
  function sponsored(el){ var a=((el.getAttribute&&el.getAttribute('aria-label'))||'').toLowerCase();
    for(var i=0;i<SP.length;i++)if(a.indexOf(SP[i])>=0)return true;
    var h=el.querySelector?el.querySelector('h3,h4,[role="link"] strong,a[role="link"]'):null;
    var p=h?txt(h):txt(el).slice(0,120); for(var j=0;j<SP.length;j++)if(p.indexOf(SP[j])>=0)return true; return false; }
  function facebook(){ if(!/facebook\./.test(location.hostname))return;
    var arts=document.querySelectorAll('[role="article"],[data-pagelet^="FeedUnit"],[aria-posinset]');
    for(var i=0;i<arts.length;i++){ var el=arts[i]; if(el.__ab)continue; el.__ab=1; if(sponsored(el))hide(el); } }
  function youtube(){ if(!/(^|\.)youtube(-nocookie)?\.com$/.test(location.hostname))return;
    var pop=document.querySelector('tp-yt-paper-dialog, ytd-popup-container tp-yt-paper-dialog');
    if(pop&&pop.querySelector&&pop.querySelector('ytd-enforcement-message-view-model')){ hide(pop);
      var bg=document.querySelector('tp-yt-iron-overlay-backdrop'); if(bg)hide(bg); }
    var players=document.querySelectorAll('.html5-video-player');
    for(var k=0;k<players.length;k++){
      var p=players[k]; var v=p.querySelector('video'); if(!v)continue;
      var showing=p.classList.contains('ad-showing')||p.classList.contains('ad-interrupting');
      if(!showing){
        if(v.__abMuted){ try{ v.muted=(v.__abMuted===2); }catch(e){} v.__abMuted=0; }
        continue; }
      var skip=p.querySelector('.ytp-ad-skip-button-modern,.ytp-ad-skip-button,.ytp-skip-ad-button');
      if(skip){ try{skip.click();}catch(e){} continue; }
      if(!v.__abMuted){ try{ v.__abMuted=v.muted?2:1; v.muted=true; }catch(e){} }
      var d=v.duration;
      if(isFinite(d)&&d>0){ try{ v.currentTime=d; }catch(e){} } } }
  var STATIC=['ins.adsbygoogle','[id^="google_ads_"]','[id^="div-gpt-ad"]','iframe[src*="/ads/"]',
    '[aria-label="Advertisement"]','[data-ad-preview]'];
  var STATIC_YT=['.video-ads','.ytp-ad-module','#player-ads','ytd-ad-slot-renderer','ytd-promoted-video-renderer',
    'ytd-in-feed-ad-layout-renderer','ytd-display-ad-renderer','ytd-promoted-sparkles-web-renderer','#masthead-ad',
    'ytd-companion-slot-renderer','ytd-enforcement-message-view-model','.ytd-enforcement-message-view-model'];
  function genericFallback(){ for(var i=0;i<STATIC.length;i++){ try{ var els=document.querySelectorAll(STATIC[i]);
    for(var j=0;j<els.length;j++)hide(els[j]); }catch(e){} } }
  function ytFallback(){ for(var i=0;i<STATIC_YT.length;i++){ try{ var els=document.querySelectorAll(STATIC_YT[i]);
    for(var j=0;j<els.length;j++)hide(els[j]); }catch(e){} } }
  var sheeted=false;
  function onYouTube(){ return /(^|\.)youtube(-nocookie)?\.com$/.test(location.hostname); }
  function toSheet(){
    var S=window.__abStyle;
    if(!S || !S.hide) return false;
    return S.hide(onYouTube() ? STATIC.concat(STATIC_YT) : STATIC);
  }
  function run(){ try{
    if(!sheeted){ sheeted=toSheet(); }
    facebook();
    youtube();
    if(!sheeted){ genericFallback(); if(onYouTube()) ytFallback(); }
  }catch(e){} }
  if(window.__abObs) window.__abObs(run);
  else { run(); try{ new MutationObserver(run).observe(document.documentElement||document.body,
                                                       {childList:true,subtree:true}); }catch(e){} }
})();
""";

    public const char Sep = (char)0x1f;

    public const string RawJsName = "__js";

    private static readonly string LibraryReady =
        Library.Replace("__AB_IMA__", AdRedirects.GoogleIma);

    public static string BuildInjection(IReadOnlyList<string> hostScriptlets)
        => BuildInjection(hostScriptlets, Array.Empty<string>());

    private const string MediaWatch ="""
(function(){
  if(window.__abMedia) return; window.__abMedia=1;
  try{
    var ZGLOSZONO=false;
    var GATE=/(^|[^a-z])(ads?|advert|preroll|midroll|vast|vpaid|ima)([^a-z]|$)/i;
    function host(u){ try{ return new URL(u, location.href).hostname; }catch(e){ return ''; } }
    function bramka(el){
      try{
        var r=document.querySelectorAll('iframe[src*="imasdk.googleapis.com"],iframe[src*="/vast"],iframe[title="Advertisement"]');
        if(r.length) return 'sdk:'+(host(r[0].getAttribute('src')||'')||'iframe');
        var p=el;
        for(var i=0;i<6&&p;i++,p=p.parentElement){
          var id=(p.id||'')+' '+((typeof p.className==='string')?p.className:'');
          if(GATE.test(id) && p.querySelector('video,audio')) return 'kontener:'+id.trim().slice(0,60);
        }
      }catch(e){}
      return '';
    }
    function opis(el){
      var e=el.error||{};
      return { tag:el.tagName, err:(e.code||0), ready:el.readyState, net:el.networkState,
               paused:!!el.paused, t:+(el.currentTime||0), zrodlo:host(el.currentSrc||el.src||'') };
    }
    function zepsuty(el, odKiedy){
      try{
        if(el.error && (el.error.code===2||el.error.code===3||el.error.code===4)) return 'blad'+el.error.code;
        if(el.networkState===3 && el.readyState===0) return 'brak-zrodla';
        if(!el.paused && el.currentTime<0.05 && Date.now()-odKiedy>8000) return 'stoi';
        if(el.__abProbowano && el.paused && el.readyState===0 && Date.now()-odKiedy>8000) return 'nie-ruszyl';
      }catch(e){}
      return '';
    }
    var start={};
    function pilnuj(el){
      if(el.__abPilnowany) return; el.__abPilnowany=1;
      var id=Math.random();
      el.__abId=id; start[id]=Date.now();
      try{ el.addEventListener('play',function(){ el.__abProbowano=1; start[id]=Date.now(); },true); }catch(e){}
      try{ el.addEventListener('error',function(){ sprawdz(el); },true); }catch(e){}
    }
    function sprawdz(el){
      if(ZGLOSZONO) return;
      if(!el.__abProbowano) return;
      var powod=zepsuty(el, start[el.__abId]||Date.now());
      if(!powod) return;
      ZGLOSZONO=true;
      var d=opis(el), g=bramka(el);
      try{ if(sessionStorage.getItem('__abMediaZgl')) return; sessionStorage.setItem('__abMediaZgl','1'); }catch(e){}
      var u='https://report.adblocker.invalid/media?host='+encodeURIComponent(location.hostname)+
            '&page='+encodeURIComponent(location.href.slice(0,300))+
            '&powod='+encodeURIComponent(powod)+
            '&tag='+encodeURIComponent(d.tag)+'&err='+d.err+'&ready='+d.ready+'&net='+d.net+
            '&zrodlo='+encodeURIComponent(d.zrodlo)+
            '&bramka='+encodeURIComponent(g);
      try{ (new Image()).src=u; }catch(e){}
    }
    function omiot(){
      try{
        var m=document.querySelectorAll('video,audio');
        for(var i=0;i<m.length&&i<40;i++){ pilnuj(m[i]); sprawdz(m[i]); }
      }catch(e){}
    }
    omiot();
    var n=0, tm=setInterval(function(){ if(++n>20||ZGLOSZONO) clearInterval(tm); omiot(); }, 2000);
    if(window.__abObs) window.__abObs(omiot);
    else { try{ new MutationObserver(function(){ omiot(); })
                  .observe(document.documentElement,{subtree:true,childList:true}); }catch(e){} }
  }catch(e){}
})();
""";

    public static string BuildInjection(IReadOnlyList<string> hostScriptlets,
                                        IReadOnlyList<string> proceduralSelectors)
    {
        var sb = new StringBuilder(LibraryReady.Length + Generic.Length + MediaWatch.Length + 256);
        sb.Append("<script id=\"adblocker-scriptlet\">");

        sb.Append("try{window.__adblockerActive=").Append(hostScriptlets.Count)
          .Append(";console.log('[Malward.NetworkScanner.AdBlock] active, scriptlets: ").Append(hostScriptlets.Count).Append("');}catch(e){}");
        sb.Append(LibraryReady);
        sb.Append(Generic);
        sb.Append(MediaWatch);
        foreach (var spec in hostScriptlets)
        {
            var parts = spec.Split(Sep);
            if (parts.Length == 0 || parts[0].Length == 0) continue;
            if (parts[0] == RawJsName)
            {
                if (parts.Length < 2) continue;
                sb.Append("try{").Append(parts[1].Replace("</script", "<\\/script")).Append("}catch(e){}");
                continue;
            }
            sb.Append("try{window.__abRun(").Append(JsStr(parts[0])).Append(",[");
            for (int i = 1; i < parts.Length; i++) { if (i > 1) sb.Append(','); sb.Append(JsStr(parts[i])); }
            sb.Append("]);}catch(e){}");
        }
        if (proceduralSelectors.Count > 0)
        {
            sb.Append(AdProcedural.Engine);
            sb.Append("try{window.__abProc([");
            for (int i = 0; i < proceduralSelectors.Count; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append(JsStr(proceduralSelectors[i]));
            }
            sb.Append("]);}catch(e){}");
        }
        sb.Append("</script>");
        return sb.ToString();
    }

    private static readonly Lazy<HashSet<string>> SupportedNames = new(() =>
    {
        var names = new HashSet<string>(StringComparer.Ordinal);

        int i = Library.IndexOf("var reg={", StringComparison.Ordinal);
        if (i < 0) return names;
        int openBrace = Library.IndexOf('{', i);
        int depth = 0, end = -1;
        for (int p = openBrace; p < Library.Length; p++)
        {
            if (Library[p] == '{') depth++;
            else if (Library[p] == '}' && --depth == 0) { end = p; break; }
        }
        if (end < 0) return names;
        foreach (System.Text.RegularExpressions.Match m in
                 System.Text.RegularExpressions.Regex.Matches(Library[openBrace..end], @"'([^']+)'\s*:"))
            names.Add(m.Groups[1].Value);
        return names;
    });

    internal static string PlainName(string name)
    {
        var n = name.EndsWith(".js", StringComparison.Ordinal) ? name[..^3] : name;
        if (n.StartsWith("ubo-", StringComparison.Ordinal)) return n[4..];
        if (n.StartsWith("abp-", StringComparison.Ordinal)) return n[4..];
        return n;
    }

    public static (int executed, List<string> skipped) Coverage(IReadOnlyList<string> specs)
    {
        var skipped = new List<string>();
        int ok = 0;
        foreach (var spec in specs)
        {
            var name = spec.Split(Sep)[0];
            if (name == RawJsName) { ok++; continue; }
            if (SupportedNames.Value.Contains(name) || SupportedNames.Value.Contains(PlainName(name))) ok++;
            else skipped.Add(name);
        }
        return (ok, skipped);
    }

    private static string JsStr(string s)
    {
        var sb = new StringBuilder(s.Length + 2);
        sb.Append('"');
        foreach (var c in s)
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '<': sb.Append("\\u003c"); break;
                default: sb.Append(c); break;
            }
        sb.Append('"');
        return sb.ToString();
    }
}
