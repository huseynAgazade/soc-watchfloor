/* SOC Watchfloor — cookie and usage-statistics choice.
   One essential cookie (the sign-in session) is always set. Usage statistics are
   counted only after "Allow usage statistics". The choice is stored in this
   browser; any element with [data-cookie-settings] reopens the banner.
   API: window.WFConsent.get() → "essential" | "all" | null, .set(v), .allowsStats(),
        .onChange(fn), .open() */
(function(){
  var KEY="wf.consent", listeners=[], box=null;
  function get(){ try{ var v=localStorage.getItem(KEY); return v==="all"||v==="essential"?v:null; }catch(e){ return null; } }
  function set(v){
    try{ localStorage.setItem(KEY, v); }catch(e){}
    hide(); listeners.forEach(function(fn){ try{ fn(v); }catch(e){} });
  }
  var CSS=".wf-consent{position:fixed;left:16px;right:16px;bottom:16px;z-index:10000;max-width:600px;margin:0 auto;"+
    "background:var(--surface,#fff);color:var(--ink,#141922);border:1px solid var(--rule-2,#cbd2dd);border-radius:12px;"+
    "box-shadow:0 18px 50px -20px rgba(20,25,34,.45);padding:16px 18px;font:13px/1.55 'IBM Plex Sans',system-ui,sans-serif}"+
    ".wf-consent h2{font-size:14px;margin:0 0 4px;font-weight:600}.wf-consent p{margin:0 0 12px;color:var(--ink-2,#525c6e)}"+
    ".wf-consent a{color:var(--accent-ink,#2a4a9c)}.wf-consent .wf-row{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}"+
    ".wf-consent button{font:inherit;font-weight:600;font-size:12.5px;padding:8px 14px;border-radius:8px;cursor:pointer;width:auto;margin:0;"+
    "border:1px solid var(--rule-2,#cbd2dd);background:var(--surface,#fff);color:var(--ink,#141922);opacity:1}"+
    ".wf-consent button:hover{border-color:var(--accent,#2a4a9c)}.wf-consent button:focus-visible{outline:2px solid var(--accent,#2a4a9c);outline-offset:2px}";
  function build(){
    var st=document.createElement("style"); st.textContent=CSS; document.head.appendChild(st);
    box=document.createElement("section"); box.className="wf-consent"; box.setAttribute("role","region");
    box.setAttribute("aria-label","Cookie choices"); box.hidden=true;
    box.innerHTML='<h2>Cookies and usage statistics</h2>'+
      '<p>Watchfloor sets one essential cookie to keep you signed in. With your permission it also counts which pages are opened — per role, never your name or address, and nothing is sent to anyone else. <a href="/privacy#cookies">Privacy policy</a></p>'+
      '<div class="wf-row"><button type="button" data-choice="essential">Essential only</button><button type="button" data-choice="all">Allow usage statistics</button></div>';
    box.addEventListener("click",function(e){ var b=e.target.closest("[data-choice]"); if(b) set(b.getAttribute("data-choice")); });
    document.body.appendChild(box);
  }
  function show(){ if(!box) build(); box.hidden=false; var b=box.querySelector("button"); if(b) b.focus({preventScroll:true}); }
  function hide(){ if(box) box.hidden=true; }
  document.addEventListener("click",function(e){ if(e.target.closest && e.target.closest("[data-cookie-settings]")){ e.preventDefault(); show(); } });
  function init(){ if(!get()){ build(); box.hidden=false; } }
  if(document.readyState==="loading") document.addEventListener("DOMContentLoaded", init); else init();
  window.WFConsent={ get:get, set:set, open:show, allowsStats:function(){ return get()==="all"; },
                     onChange:function(fn){ listeners.push(fn); } };
})();
