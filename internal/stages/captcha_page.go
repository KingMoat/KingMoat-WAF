package stages

import (
	"crypto/rand"
	"fmt"
	"strings"
)

// renderSVG draws the challenge background: geometric noise plus the target
// gap. The gap position is visual only — its numeric value is carried in the
// MAC-protected token, not in the DOM.
func renderSVG(gapX int) string {
	var sb strings.Builder
	sb.WriteString(`<svg class="km-bg" width="320" height="140" viewBox="0 0 320 140" xmlns="http://www.w3.org/2000/svg">`)
	seed := randInt(256)
	for i := 0; i < 14; i++ {
		x, y := randInt(320), randInt(140)
		w, h := 20+randInt(70), 10+randInt(50)
		colors := []string{"#5b8def", "#7f6bd8", "#3fa8a0", "#c86f5a", "#8a9b3f"}
		c := colors[(seed+i)%len(colors)]
		switch (seed + i) % 3 {
		case 0:
			fmt.Fprintf(&sb, `<rect x="%d" y="%d" width="%d" height="%d" rx="6" fill="%s" opacity="0.35"/>`, x, y, w, h, c)
		case 1:
			fmt.Fprintf(&sb, `<circle cx="%d" cy="%d" r="%d" fill="%s" opacity="0.3"/>`, x, y, 8+randInt(24), c)
		default:
			fmt.Fprintf(&sb, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="3" opacity="0.4"/>`, x, y, (x+w)%320, (y+h)%140, c)
		}
	}
	// target gap: white rounded square with dashed outline
	fmt.Fprintf(&sb, `<rect x="%d" y="44" width="36" height="36" rx="8" fill="rgba(255,255,255,0.9)" stroke="#334" stroke-width="2" stroke-dasharray="5,4"/>`, gapX)
	// the draggable piece starts on the left
	sb.WriteString(`<rect x="8" y="44" width="36" height="36" rx="8" fill="#2b3a67" opacity="0.9" class="km-piece"/>`)
	sb.WriteString(`</svg>`)
	return sb.String()
}

func randInt(n int) int {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return int(b[0]) % n
}

// sliderPage renders the self-contained challenge page.
func sliderPage(svg, token, back string) string {
	return fmt.Sprintf(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>人机验证</title>
<style>
body{font-family:system-ui,sans-serif;background:#eef1f5;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#fff;border-radius:12px;padding:24px;box-shadow:0 4px 24px rgba(0,0,0,.08);width:340px}
h3{margin:0 0 12px;font-size:16px;color:#1f2329}
.track{position:relative;width:320px;height:140px;overflow:hidden;border-radius:8px;background:#5b8def22}
.track svg{position:absolute;left:0;top:0}
.bar{margin-top:12px;position:relative;width:320px;height:40px;background:#e5e6eb;border-radius:20px}
.knob{position:absolute;left:4px;top:4px;width:48px;height:32px;border-radius:16px;background:#2b3a67;color:#fff;text-align:center;line-height:32px;cursor:grab;user-select:none;font-size:16px}
.fill{position:absolute;left:0;top:0;height:100%%;border-radius:20px 0 0 20px;background:#2b3a6722;width:52px}
.msg{margin-top:10px;font-size:13px;color:#86909c;min-height:18px}
.err{color:#d4380d}
</style></head><body>
<div class="card">
<h3>拖动滑块完成验证</h3>
<div class="track">%s</div>
<div class="bar"><div class="fill"></div><div class="knob" id="knob">&#8596;</div></div>
<div class="msg" id="msg">按住滑块，拖动到缺口位置</div>
</div>
<script>
(function(){
var knob=document.getElementById('knob'),msg=document.getElementById('msg');
var back='%s';
var startX=0,dragX=0,dragging=false;
function piece(){return document.querySelector('.km-piece')}
function setX(px){px=Math.max(0,Math.min(px,320-52));dragX=px;knob.style.left=(4+px)+'px';
var f=document.querySelector('.fill');if(f)f.style.width=(52+px)+'px';
var p=piece();if(p)p.setAttribute('x',8+px);}
knob.addEventListener('pointerdown',function(e){dragging=true;startX=e.clientX-dragX;knob.setPointerCapture(e.pointerId);});
knob.addEventListener('pointermove',function(e){if(!dragging)return;setX(e.clientX-startX);});
knob.addEventListener('pointerup',function(e){
dragging=false;
var x=Math.round(dragX+8+18); // center of the piece
msg.className='msg';msg.textContent='验证中…';
fetch('%s?token=%s&x='+x+'&back='+encodeURIComponent(back),{credentials:'same-origin'})
.then(function(r){return r.json().then(function(j){return {code:r.status,j:j}})})
.then(function(o){
if(o.code===200&&o.j&&o.j.ok){msg.textContent='验证通过，正在进入…';setTimeout(function(){location.replace(back)},300);}
else{msg.className='msg err';msg.textContent='未对准缺口，重试';setX(0);setTimeout(function(){location.reload()},800);}
})
.catch(function(){msg.className='msg err';msg.textContent='网络错误，请重试';setX(0);});
});
})();
</script>
</body></html>`, svg, back, CaptchaVerifyPath, token)
}
