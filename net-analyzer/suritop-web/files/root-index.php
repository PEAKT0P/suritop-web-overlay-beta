<?php
$ip = $_SERVER["HTTP_HOST"] ?? "";
?>
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Suritop-Web Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;overflow:hidden;background:#0a0e14;font-family:"JetBrains Mono","Share Tech Mono",monospace}
.frame{display:flex;height:100vh;width:100vw}
.panel{position:relative;overflow:hidden;border:1px solid rgba(255,255,255,0.04)}
.panel iframe{width:100%;height:100%;border:none;background:#0a0e14}
.panel-label{position:absolute;top:4px;left:8px;z-index:10;font-size:9px;font-weight:700;letter-spacing:1.5px;color:rgba(255,255,255,0.35);pointer-events:none;text-transform:uppercase}
.left{flex:0 0 50%;display:flex;flex-direction:column}
.right{flex:1;display:flex;flex-direction:column;position:relative}
.right-top{flex:1;position:relative;overflow:hidden}
.right-bottom{flex:1;position:relative;overflow:hidden}
.h-splitter{width:4px;cursor:col-resize;background:rgba(255,59,48,0.15);flex-shrink:0;transition:background 0.2s}
.h-splitter:hover,.h-splitter.active{background:rgba(255,59,48,0.6)}
.v-splitter{height:4px;cursor:row-resize;background:rgba(255,59,48,0.15);flex-shrink:0;transition:background 0.2s}
.v-splitter:hover,.v-splitter.active{background:rgba(255,59,48,0.6)}
.logo{position:fixed;top:6px;right:12px;z-index:100;font-size:8px;letter-spacing:2px;color:rgba(255,59,48,0.3);font-weight:700;pointer-events:none}
</style>
</head>
<body>
<div class="logo">SURITOP</div>
<div class="frame">
  <div class="left panel" id="leftPanel">
    <span class="panel-label">&#x2694; Threat Map</span>
    <iframe src="attackmap/" loading="lazy"></iframe>
  </div>
  <div class="h-splitter" id="hSplitter"></div>
  <div class="right" id="rightPanel">
    <div class="right-top panel" id="topPanel">
      <span class="panel-label">&#x1f4ca; Admin Stats</span>
      <iframe src="admin_stats.php" loading="lazy"></iframe>
    </div>
    <div class="v-splitter" id="vSplitter"></div>
    <div class="right-bottom panel" id="bottomPanel">
      <span class="panel-label">&#x26e2; Firewall</span>
      <iframe src="iptables/" loading="lazy"></iframe>
    </div>
  </div>
</div>
<script>
(function(){
  var left=document.getElementById("leftPanel"),
      right=document.getElementById("rightPanel"),
      hSp=document.getElementById("hSplitter"),
      vSp=document.getElementById("vSplitter"),
      top=document.getElementById("topPanel"),
      bot=document.getElementById("bottomPanel");

  hSp.addEventListener("mousedown",function(e){
    e.preventDefault();hSp.classList.add("active");
    var startX=e.clientX,startW=left.offsetWidth;
    function onMove(ev){
      var nw=Math.max(200,startW+(ev.clientX-startX));
      left.style.flex="0 0 "+nw+"px";
    }
    function onUp(){hSp.classList.remove("active");document.removeEventListener("mousemove",onMove);document.removeEventListener("mouseup",onUp)}
    document.addEventListener("mousemove",onMove);
    document.addEventListener("mouseup",onUp);
  });

  vSp.addEventListener("mousedown",function(e){
    e.preventDefault();vSp.classList.add("active");
    var startY=e.clientY,startH=top.offsetHeight;
    function onMove(ev){
      var nh=Math.max(100,startH+(ev.clientY-startY));
      top.style.flex="none";top.style.height=nh+"px";
    }
    function onUp(){vSp.classList.remove("active");document.removeEventListener("mousemove",onMove);document.removeEventListener("mouseup",onUp)}
    document.addEventListener("mousemove",onMove);
    document.addEventListener("mouseup",onUp);
  });
})();
</script>
</body>
</html>
