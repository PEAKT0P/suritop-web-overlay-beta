#!/usr/bin/env python3
"""
suritop v4 — Suricata IDS + ModSecurity WAF Monitor
Matrix/Cyber theme with noise filtering and detail view.

Launch: suritop
Keys:   q/Esc=quit  p=pause  c=clear  f=filter  d=detail
        1-3=sort  ↑↓=scroll  TAB=cycle panels
        PgUp/PgDn=fast scroll  Home=top
"""

import sys
import curses
sys.path.insert(0, '/usr/libexec/suritop-web')
from suritop_config import get_config
import json
import os
import time
import configparser
from collections import defaultdict, deque
from datetime import datetime, timedelta

# ── Читаем конфиг ──
config = configparser.ConfigParser()
config.read('/usr/libexec/suritop-web/collector.conf')
# Берем IP, а если файла нет или там ошибка — используем старый IP как запасной
OUR_IP = config.get('Network', 'our_ip', fallback='127.0.0.1')

EVE_LOG = '/var/log/suricata/eve.json'
MAX_ALERTS = 500
MAX_WAF = 200
REFRESH_MS = 400
WAF_POLL_SEC = 5

SKIP_PREFIXES = [
    'SURICATA STREAM','SURICATA Applayer','SURICATA QUIC',
    'SURICATA TLS','SURICATA HTTP','SURICATA SMB',
    'ET INFO Session Traversal Utilities',
    'ET INFO Android Device Connectivity',
    'ET INFO Microsoft Connection Test',
    'ET INFO Observed Google DNS',
    'ET INFO possible Xiaomi phone',
    'ET INFO Observed DNS Query to vk.com',
]
def _get_local_ips():
    """Определяем локальные IP динамически"""
    ips = {OUR_IP}
    try:
        import socket
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        ips.add(local_ip)
    except Exception:
        pass
    # Добавляем все адреса основного интерфейса
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for a in addrs:
                ips.add(a['addr'])
    except ImportError:
        pass
    # Добавляем стандартные приватные подсети шлюзов
    ips.update({'10.0.0.1', '172.16.0.1', '192.168.0.1'})
    return ips

LOCAL_IPS = _get_local_ips()

_db_cfg = get_config()
DB_HOST = _db_cfg["db_host"]
DB_USER = _db_cfg["db_user_w"]
DB_PASS = _db_cfg["db_pass_w"]
DB_NAME = _db_cfg["db_name"]

try:
    import MySQLdb; HAS_MYSQL=True
except ImportError:
    try: import pymysql as MySQLdb; HAS_MYSQL=True
    except ImportError: HAS_MYSQL=False

BOX_H='─'; BOX_V='│'; BOX_TL='┌'; BOX_TR='┐'; BOX_BL='└'; BOX_BR='┘'; DOT_H='·'

C_BORDER=1;C_TITLE=2;C_CRIT=3;C_WARN=4;C_INFO=5
C_IP=6;C_VAL=7;C_DIM=8;C_OK=9;C_HDR=10
C_LIVE=11;C_BAR=12;C_PROTO=13;C_PORT=14;C_LABEL=15
C_WAF=16;C_WAF_HDR=17;C_LOCAL=18;C_DETAIL=19;C_FILTERED=20

class SuriTop:
    def __init__(self):
        self.alerts=deque(maxlen=MAX_ALERTS); self.filtered_count=0
        self.top_ips=defaultdict(lambda:{'count':0,'last':'','sigs':set(),'ports':set()})
        self.top_sigs=defaultdict(int); self.total_alerts=0
        self.minute_counts=deque(maxlen=60); self.current_minute_count=0
        self.last_minute=datetime.now().minute; self.alerts_per_min=0.0
        self.eve_offset=0; self.eve_inode=0
        self.proto_counts=defaultdict(int)
        self.packets=0; self.drops=0; self.uptime=0
        self.waf_blocks=deque(maxlen=MAX_WAF)
        self.waf_total=0; self.waf_today=0
        self.waf_top_rules=defaultdict(int); self.waf_top_ips=defaultdict(int)
        self.waf_last_id=0; self.waf_last_poll=0
        self.db_conn=None; self.db_ok=False
        self.paused=False; self.sort_mode=0
        self.scrolls=[0,0,0,0]; self.active_panel=0
        self.filter_noise=True; self.show_detail=False
        self.sev_name={1:'CRIT',2:'WARN',3:'INFO'}; self.sev_color={}

    def _is_noise(self,sig):
        for p in SKIP_PREFIXES:
            if sig.startswith(p): return True
        return False

    def init_colors(self):
        curses.start_color(); curses.use_default_colors()
        u=curses.COLORS>=256
        if u:
            G=46;DG=34;CY=51;YL=226;RD=196;OR=208;MG=135;DM=240;DKG=22
            curses.init_pair(C_BORDER,DG,-1);curses.init_pair(C_TITLE,G,-1)
            curses.init_pair(C_CRIT,RD,-1);curses.init_pair(C_WARN,OR,-1)
            curses.init_pair(C_INFO,CY,-1);curses.init_pair(C_IP,G,-1)
            curses.init_pair(C_VAL,CY,-1);curses.init_pair(C_DIM,DM,-1)
            curses.init_pair(C_OK,G,-1);curses.init_pair(C_HDR,CY,-1)
            curses.init_pair(C_LIVE,G,-1);curses.init_pair(C_BAR,DG,-1)
            curses.init_pair(C_PROTO,YL,-1);curses.init_pair(C_PORT,MG,-1)
            curses.init_pair(C_LABEL,DM,-1);curses.init_pair(C_WAF,OR,-1)
            curses.init_pair(C_WAF_HDR,OR,-1);curses.init_pair(C_LOCAL,DM,-1)
            curses.init_pair(C_DETAIL,CY,DKG);curses.init_pair(C_FILTERED,DM,-1)
        else:
            curses.init_pair(C_BORDER,curses.COLOR_GREEN,-1)
            curses.init_pair(C_TITLE,curses.COLOR_GREEN,-1)
            curses.init_pair(C_CRIT,curses.COLOR_RED,-1)
            curses.init_pair(C_WARN,curses.COLOR_YELLOW,-1)
            curses.init_pair(C_INFO,curses.COLOR_CYAN,-1)
            curses.init_pair(C_IP,curses.COLOR_GREEN,-1)
            curses.init_pair(C_VAL,curses.COLOR_CYAN,-1)
            curses.init_pair(C_DIM,curses.COLOR_WHITE,-1)
            curses.init_pair(C_OK,curses.COLOR_GREEN,-1)
            curses.init_pair(C_HDR,curses.COLOR_CYAN,-1)
            curses.init_pair(C_LIVE,curses.COLOR_GREEN,-1)
            curses.init_pair(C_BAR,curses.COLOR_GREEN,-1)
            curses.init_pair(C_PROTO,curses.COLOR_YELLOW,-1)
            curses.init_pair(C_PORT,curses.COLOR_MAGENTA,-1)
            curses.init_pair(C_LABEL,curses.COLOR_WHITE,-1)
            curses.init_pair(C_WAF,curses.COLOR_YELLOW,-1)
            curses.init_pair(C_WAF_HDR,curses.COLOR_YELLOW,-1)
            curses.init_pair(C_LOCAL,curses.COLOR_WHITE,-1)
            curses.init_pair(C_DETAIL,curses.COLOR_CYAN,curses.COLOR_BLACK)
            curses.init_pair(C_FILTERED,curses.COLOR_WHITE,-1)
        self.sev_color={1:curses.color_pair(C_CRIT)|curses.A_BOLD,2:curses.color_pair(C_WARN),3:curses.color_pair(C_INFO)}

    def db_connect(self):
        if not HAS_MYSQL: return
        try:
            self.db_conn=MySQLdb.connect(host=DB_HOST,user=DB_USER,passwd=DB_PASS,db=DB_NAME,charset='utf8mb4',connect_timeout=3,read_timeout=3)
            self.db_conn.autocommit(True); self.db_ok=True
        except: self.db_ok=False

    def poll_waf(self):
        now=time.time()
        if now-self.waf_last_poll<WAF_POLL_SEC: return
        self.waf_last_poll=now
        if not self.db_ok: self.db_connect()
        if not self.db_ok or not self.db_conn: return
        try:
            cur=self.db_conn.cursor()
            cur.execute("SELECT id,src_ip,host,uri,method,rule_id,rule_msg,severity,logged_at FROM waf_blocks WHERE id>%s ORDER BY id ASC LIMIT 50",(self.waf_last_id,))
            for row in cur.fetchall():
                wid,src_ip,host,uri,method,rule_id,rule_msg,sev,logged_at=row
                self.waf_last_id=max(self.waf_last_id,wid)
                self.waf_blocks.appendleft({'id':wid,'ip':src_ip,'host':(host or '')[:30],'uri':(uri or '')[:80],'method':method or 'GET','rule_id':rule_id,'rule_msg':rule_msg or '','severity':sev or 0,'time':logged_at.strftime('%H:%M:%S') if logged_at else '—','date':logged_at.strftime('%Y-%m-%d') if logged_at else ''})
                self.waf_total+=1; self.waf_top_rules[rule_msg or 'Unknown']+=1; self.waf_top_ips[src_ip]+=1
            cur.execute("SELECT COUNT(*) FROM waf_blocks WHERE logged_at>=CURDATE()")
            r=cur.fetchone(); self.waf_today=r[0] if r else 0; cur.close()
        except:
            self.db_ok=False
            try: self.db_conn.close()
            except: pass
            self.db_conn=None

    def _load_waf_initial(self):
        if not self.db_ok or not self.db_conn: return
        try:
            cur=self.db_conn.cursor()
            cur.execute("SELECT id,src_ip,host,uri,method,rule_id,rule_msg,severity,logged_at FROM waf_blocks ORDER BY id DESC LIMIT 50")
            for row in reversed(cur.fetchall()):
                wid,src_ip,host,uri,method,rule_id,rule_msg,sev,logged_at=row
                self.waf_last_id=max(self.waf_last_id,wid)
                self.waf_blocks.appendleft({'id':wid,'ip':src_ip,'host':(host or '')[:30],'uri':(uri or '')[:80],'method':method or 'GET','rule_id':rule_id,'rule_msg':rule_msg or '','severity':sev or 0,'time':logged_at.strftime('%H:%M:%S') if logged_at else '—','date':logged_at.strftime('%Y-%m-%d') if logged_at else ''})
                self.waf_total+=1; self.waf_top_rules[rule_msg or 'Unknown']+=1; self.waf_top_ips[src_ip]+=1
            cur.close()
        except: pass

    def read_eve(self):
        if not os.path.exists(EVE_LOG): return []
        try: stat=os.stat(EVE_LOG)
        except OSError: return []
        if stat.st_ino!=self.eve_inode: self.eve_inode=stat.st_ino; self.eve_offset=0
        if stat.st_size<self.eve_offset: self.eve_offset=0
        if stat.st_size==self.eve_offset: return []
        new=[]
        try:
            with open(EVE_LOG,'r',errors='replace') as f:
                f.seek(self.eve_offset)
                for line in f:
                    line=line.strip()
                    if not line: continue
                    try: ev=json.loads(line)
                    except: continue
                    et=ev.get('event_type','')
                    if et=='stats':
                        s=ev.get('stats',{});cap=s.get('capture',{})
                        self.packets=cap.get('kernel_packets',self.packets)
                        self.drops=cap.get('kernel_drops',self.drops)
                        self.uptime=s.get('uptime',self.uptime)
                    elif et=='alert':
                        al=ev.get('alert',{})
                        new.append({'time':ev.get('timestamp','')[:19].replace('T',' '),'src_ip':ev.get('src_ip','?'),'dst_ip':ev.get('dest_ip','?'),'dst_port':ev.get('dest_port',0),'src_port':ev.get('src_port',0),'proto':ev.get('proto','?'),'sig_msg':al.get('signature','?'),'severity':al.get('severity',3),'sig_id':al.get('signature_id',0),'category':al.get('category',''),'http_host':ev.get('http',{}).get('hostname',''),'http_url':ev.get('http',{}).get('url',''),'http_ua':ev.get('http',{}).get('http_user_agent','')})
                self.eve_offset=f.tell()
        except: pass
        return new

    def process_alerts(self,alerts):
        for a in alerts:
            if self._is_noise(a['sig_msg']):
                self.filtered_count+=1
                if self.filter_noise: continue
            self.alerts.appendleft(a); self.total_alerts+=1; self.current_minute_count+=1
            ip=a['src_ip']; self.top_ips[ip]['count']+=1; self.top_ips[ip]['last']=a['time']
            self.top_ips[ip]['sigs'].add(a['sig_id']); self.top_ips[ip]['ports'].add(a['dst_port'])
            self.proto_counts[a['proto']]+=1
            sig=a['sig_msg']
            for pfx in ('ET ','SURICATA '):
                if sig.startswith(pfx): sig=sig[len(pfx):]
            self.top_sigs[sig]+=1

    def update_rates(self):
        now=datetime.now()
        if now.minute!=self.last_minute:
            self.minute_counts.append(self.current_minute_count); self.current_minute_count=0; self.last_minute=now.minute
        if self.minute_counts: self.alerts_per_min=sum(self.minute_counts)/len(self.minute_counts)

    def clear_stats(self):
        self.alerts.clear();self.top_ips.clear();self.top_sigs.clear()
        self.proto_counts.clear();self.total_alerts=0;self.filtered_count=0
        self.minute_counts.clear();self.current_minute_count=0;self.scrolls=[0,0,0,0]
        self.waf_blocks.clear();self.waf_total=0;self.waf_top_rules.clear();self.waf_top_ips.clear()

    def _s(self,scr,y,x,text,attr=0):
        h,w=scr.getmaxyx()
        if 0<=y<h and 0<=x<w:
            try: scr.addnstr(y,x,text,w-x,attr)
            except curses.error: pass

    def _hline(self,scr,y,x1,x2,attr=None):
        if attr is None: attr=curses.color_pair(C_BORDER)
        w=scr.getmaxyx()[1]
        for i in range(x1,min(x2,w)): self._s(scr,y,i,BOX_H,attr)

    def _vline(self,scr,x,y1,y2,attr=None):
        if attr is None: attr=curses.color_pair(C_BORDER)
        h=scr.getmaxyx()[0]
        for i in range(y1,min(y2,h)): self._s(scr,i,x,BOX_V,attr)

    def _box(self,scr,y,x,bh,bw,title='',tc=None,active=False):
        ba=curses.color_pair(C_OK) if active else curses.color_pair(C_BORDER)
        self._s(scr,y,x,BOX_TL,ba);self._s(scr,y,x+bw-1,BOX_TR,ba)
        self._s(scr,y+bh-1,x,BOX_BL,ba);self._s(scr,y+bh-1,x+bw-1,BOX_BR,ba)
        self._hline(scr,y,x+1,x+bw-1,ba);self._hline(scr,y+bh-1,x+1,x+bw-1,ba)
        self._vline(scr,x,y+1,y+bh-1,ba);self._vline(scr,x+bw-1,y+1,y+bh-1,ba)
        if title:
            if tc is None: tc=curses.color_pair(C_HDR)|curses.A_BOLD
            self._s(scr,y,x+2,f' {title} ',tc)

    def _bar(self,scr,y,x,width,ratio,attr=None):
        if attr is None: attr=curses.color_pair(C_BAR)
        full=int(ratio*width)
        self._s(scr,y,x,('█'*full).ljust(width,'░')[:width],attr)

    @staticmethod
    def _fmt(n):
        if n>=1_000_000: return f"{n/1_000_000:.1f}M"
        if n>=1_000: return f"{n/1_000:.1f}K"
        return str(n)

    def draw(self,scr):
        scr.timeout(REFRESH_MS);curses.curs_set(0);self.init_colors()
        if HAS_MYSQL:
            self.db_connect()
            if self.db_ok: self._load_waf_initial()
        if os.path.exists(EVE_LOG):
            st=os.stat(EVE_LOG);self.eve_inode=st.st_ino
            self.eve_offset=max(0,st.st_size-2_000_000)
            self.process_alerts(self.read_eve())
        while True:
            key=scr.getch()
            if key in(ord('q'),ord('Q'),27): break
            elif key in(ord('p'),ord('P')): self.paused=not self.paused
            elif key in(ord('c'),ord('C')): self.clear_stats()
            elif key in(ord('f'),ord('F')): self.filter_noise=not self.filter_noise
            elif key in(ord('d'),ord('D')): self.show_detail=not self.show_detail
            elif key==ord('1'): self.sort_mode=0
            elif key==ord('2'): self.sort_mode=1
            elif key==ord('3'): self.sort_mode=2
            elif key==9: self.active_panel=(self.active_panel+1)%4
            elif key==curses.KEY_BTAB: self.active_panel=(self.active_panel-1)%4
            elif key==curses.KEY_UP: self.scrolls[self.active_panel]=max(0,self.scrolls[self.active_panel]-1)
            elif key==curses.KEY_DOWN: self.scrolls[self.active_panel]+=1
            elif key==curses.KEY_PPAGE: self.scrolls[self.active_panel]=max(0,self.scrolls[self.active_panel]-10)
            elif key==curses.KEY_NPAGE: self.scrolls[self.active_panel]+=10
            elif key==curses.KEY_HOME: self.scrolls[self.active_panel]=0
            if not self.paused:
                new=self.read_eve()
                if new: self.process_alerts(new)
                self.update_rates(); self.poll_waf()
            try:
                scr.erase();h,w=scr.getmaxyx()
                if h<12 or w<60:
                    self._s(scr,0,0,"Terminal too small (60x12 min)",curses.color_pair(C_CRIT))
                    scr.refresh();continue
                self._layout(scr,h,w)
                if self.show_detail: self._draw_detail(scr,h,w)
                scr.refresh()
            except curses.error: pass

    def _layout(self,scr,h,w):
        ba=curses.color_pair(C_BORDER)
        # Top bar with dot pattern
        for i in range(w):
            self._s(scr,0,i,DOT_H if i%2==0 else BOX_H,ba)
        title="SURITOP — IDS + WAF Monitor"
        self._s(scr,0,(w-len(title))//2,f" {title} ",curses.color_pair(C_TITLE)|curses.A_BOLD)
        if self.paused: self._s(scr,0,w-10," PAUSED ",curses.color_pair(C_WARN)|curses.A_BOLD)
        else:
            bl='●' if int(time.time()*2)%2 else '○'
            self._s(scr,0,w-9,f" {bl} LIVE ",curses.color_pair(C_LIVE)|curses.A_BOLD)
        self._draw_stats(scr,1,w);self._hline(scr,3,0,w,ba)
        split=int(w*0.58);bt=4;bh=h-5
        ids_h=max(5,(bh*2)//3);waf_h=bh-ids_h
        if waf_h<4: ids_h=bh-4;waf_h=4
        ft='F' if self.filter_noise else 'f'
        self._box(scr,bt,0,ids_h,split,f"IDS ALERTS ({self.total_alerts}) [{ft}={self.filtered_count}]",active=self.active_panel==0)
        self._draw_alerts(scr,bt+1,1,split-2,ids_h-2)
        db_tag="●" if self.db_ok else "○"
        self._box(scr,bt+ids_h,0,waf_h,split,f"WAF BLOCKS {db_tag} ({self.waf_today} today)",tc=curses.color_pair(C_WAF_HDR)|curses.A_BOLD,active=self.active_panel==1)
        self._draw_waf(scr,bt+ids_h+1,1,split-2,waf_h-2)
        rw=w-split;th=bh//2;bth=bh-th
        self._box(scr,bt,split,th,rw,"TOP ATTACKERS",active=self.active_panel==2)
        self._draw_top_ips(scr,bt+1,split+1,rw-2,th-2)
        self._box(scr,bt+th,split,bth,rw,"TOP SIGNATURES",active=self.active_panel==3)
        self._draw_top_sigs(scr,bt+th+1,split+1,rw-2,bth-2)
        by=h-1;self._hline(scr,by,0,w,ba)
        pn=['IDS','WAF','ATK','SIG'][self.active_panel]
        keys=f" q:quit p:pause c:clear f:filter d:detail 1-3:sort ↑↓PgUp/Dn TAB:{pn}"
        self._s(scr,by,1,keys[:w-2],curses.color_pair(C_DIM))
        if self.minute_counts:
            sp='▁▂▃▄▅▆▇█';vals=list(self.minute_counts)[-min(12,w//5):]
            mx=max(max(vals),1);bar=''.join(sp[min(int(v/mx*7),7)] for v in vals)
            self._s(scr,by,w-len(bar)-7,f"rate:{bar}",curses.color_pair(C_OK))

    def _draw_stats(self,scr,y,w):
        up=str(timedelta(seconds=self.uptime)).split('.')[0] if self.uptime else '—'
        dp=f"{self.drops/self.packets*100:.3f}%" if self.packets>0 else "0%"
        today_str=datetime.now().strftime('%Y-%m-%d')
        ids_today=sum(1 for a in self.alerts if a['time'].startswith(today_str))
        proto=' '.join(f"{p}:{c}" for p,c in sorted(self.proto_counts.items(),key=lambda x:-x[1])[:3])
        items=[('UP',up,C_OK),('PKT',self._fmt(self.packets),C_VAL),('DROP',f"{self._fmt(self.drops)}({dp})",C_CRIT if self.drops>100 else C_DIM),('IDS',str(ids_today),C_WARN),('WAF',str(self.waf_today),C_WAF),('FILT',str(self.filtered_count),C_FILTERED),('RATE',f"{self.alerts_per_min:.1f}/m",C_VAL)]
        col=1
        for lbl,val,c in items:
            need=len(lbl)+len(val)+3
            if col+need>w: break
            self._s(scr,y,col,lbl,curses.color_pair(C_LABEL))
            self._s(scr,y,col+len(lbl),':',curses.color_pair(C_BORDER))
            self._s(scr,y,col+len(lbl)+1,val,curses.color_pair(c)|curses.A_BOLD)
            col+=need
        now_s=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self._s(scr,y+1,1,now_s,curses.color_pair(C_DIM))
        if proto: self._s(scr,y+1,22,f"PROTO:{proto}",curses.color_pair(C_PROTO))
        st="▶ MONITORING" if not self.paused else "⏸ PAUSED"
        self._s(scr,y+1,w-len(st)-2,st,curses.color_pair(C_OK if not self.paused else C_WARN)|curses.A_BOLD)

    def _draw_alerts(self,scr,y,x,width,rows):
        hdr=f"{'TIME':>8} {'SEV':4} {'SOURCE IP':<15} {'PORT':>6} {'SIGNATURE'}"
        self._s(scr,y,x,hdr[:width],curses.color_pair(C_HDR)|curses.A_UNDERLINE)
        vis=list(self.alerts);start=min(self.scrolls[0],max(0,len(vis)-rows+1));self.scrolls[0]=start;vis=vis[start:start+rows-1]
        for i,a in enumerate(vis):
            row=y+1+i
            if i>=rows-1: break
            sev=a['severity'];color=self.sev_color.get(sev,curses.color_pair(C_DIM))
            tag=self.sev_name.get(sev,'???');tm=a['time'][11:19] if len(a['time'])>=19 else '??:??:??'
            sig=a['sig_msg']
            for pfx in ('ET ','SURICATA '):
                if sig.startswith(pfx): sig=sig[len(pfx):]
            is_local=a['src_ip'] in LOCAL_IPS;is_new=False
            try:
                at=datetime.strptime(a['time'],'%Y-%m-%d %H:%M:%S')
                if (datetime.now()-at).total_seconds()<15: is_new=True
            except: pass
            ip_c=curses.color_pair(C_LOCAL) if is_local else curses.color_pair(C_IP)
            if is_new: ip_c|=curses.A_BOLD
            sig_c=curses.color_pair(C_LOCAL) if is_local else color
            self._s(scr,row,x,tm,curses.color_pair(C_DIM))
            self._s(scr,row,x+9,tag,color)
            self._s(scr,row,x+14,a['src_ip'][:15].ljust(15),ip_c)
            self._s(scr,row,x+30,f":{a['dst_port']}".ljust(6),curses.color_pair(C_PORT))
            sw=max(0,width-37);self._s(scr,row,x+37,sig[:sw],sig_c)
            if is_new: self._s(scr,row,x+width-1,'◀',curses.color_pair(C_LIVE)|curses.A_BOLD)

    def _draw_waf(self,scr,y,x,width,rows):
        hdr=f"{'TIME':>8} {'IP':<15} {'MTD':>4} {'HOST':<16} {'URI'}"
        self._s(scr,y,x,hdr[:width],curses.color_pair(C_WAF_HDR)|curses.A_UNDERLINE)
        vis=list(self.waf_blocks);start=min(self.scrolls[1],max(0,len(vis)-rows+1));self.scrolls[1]=start;vis=vis[start:start+rows-1]
        for i,w in enumerate(vis):
            row=y+1+i
            if i>=rows-1: break
            is_new=False
            try:
                if w.get('date')==datetime.now().strftime('%Y-%m-%d'):
                    p=w['time'].split(':');t=int(p[0])*3600+int(p[1])*60+int(p[2])
                    n=datetime.now();now_s=n.hour*3600+n.minute*60+n.second
                    if 0<=now_s-t<30: is_new=True
            except: pass
            wc=curses.color_pair(C_WAF)
            self._s(scr,row,x,w['time'],curses.color_pair(C_DIM))
            self._s(scr,row,x+9,w['ip'][:15].ljust(15),wc|(curses.A_BOLD if is_new else 0))
            mc=C_CRIT if w['method']=='POST' else C_WARN
            self._s(scr,row,x+25,w['method'][:4].ljust(4),curses.color_pair(mc))
            host=w['host'].replace('www.','')[:16]
            self._s(scr,row,x+30,host.ljust(16),curses.color_pair(C_DIM))
            rest_w=max(0,width-47);uri_short=w['uri'][:rest_w//2]
            rule_short=w['rule_msg'][:rest_w-len(uri_short)-1]
            self._s(scr,row,x+47,uri_short,curses.color_pair(C_INFO))
            self._s(scr,row,x+47+len(uri_short)+1,rule_short,wc)
            if is_new: self._s(scr,row,x+width-1,'◀',wc|curses.A_BOLD)

    def _draw_top_ips(self,scr,y,x,width,rows):
        marks=['▼' if self.sort_mode==i else ' ' for i in range(3)]
        hdr=f"{'IP':<15} {marks[0]}Hit {marks[1]}Last     {marks[2]}Sg Pt"
        self._s(scr,y,x,hdr[:width],curses.color_pair(C_HDR)|curses.A_UNDERLINE)
        items=list(self.top_ips.items())
        if self.sort_mode==0: items.sort(key=lambda i:i[1]['count'],reverse=True)
        elif self.sort_mode==1: items.sort(key=lambda i:i[1]['last'],reverse=True)
        else: items.sort(key=lambda i:i[0])
        start=min(self.scrolls[2],max(0,len(items)-rows+1));self.scrolls[2]=start;items=items[start:]
        mx=items[0][1]['count'] if items else 1
        for i,(ip,d) in enumerate(items[:rows-1]):
            row=y+1+i
            if i>=rows-1: break
            last=d['last'][11:19] if len(d['last'])>=19 else '—'
            cnt=d['count'];ratio=cnt/max(mx,1)
            is_local=ip in LOCAL_IPS;ip_c=curses.color_pair(C_LOCAL) if is_local else curses.color_pair(C_IP)
            self._s(scr,row,x,ip[:15].ljust(15),ip_c)
            self._s(scr,row,x+16,str(cnt).rjust(4),curses.color_pair(C_VAL)|curses.A_BOLD)
            bw=min(4,max(0,width-38))
            if bw>0: self._bar(scr,row,x+21,bw,ratio)
            self._s(scr,row,x+21+bw+1,last,curses.color_pair(C_DIM))
            self._s(scr,row,x+21+bw+10,str(len(d['sigs'])).rjust(2),curses.color_pair(C_WARN))
            self._s(scr,row,x+21+bw+13,str(len(d['ports'])).rjust(2),curses.color_pair(C_PORT))

    def _draw_top_sigs(self,scr,y,x,width,rows):
        hdr=f"{'CNT':>5} {'SIGNATURE'}"
        self._s(scr,y,x,hdr[:width],curses.color_pair(C_HDR)|curses.A_UNDERLINE)
        items=sorted(self.top_sigs.items(),key=lambda i:i[1],reverse=True)
        start=min(self.scrolls[3],max(0,len(items)-rows+1));self.scrolls[3]=start;items=items[start:]
        mx=items[0][1] if items else 1
        for i,(sig,cnt) in enumerate(items[:rows-1]):
            row=y+1+i
            if i>=rows-1: break
            ratio=cnt/max(mx,1);bw=min(5,max(0,width-len(sig)-8))
            self._s(scr,row,x,str(cnt).rjust(5),curses.color_pair(C_VAL)|curses.A_BOLD)
            if bw>0: self._bar(scr,row,x+6,bw,ratio)
            sw=max(0,width-6-bw-1)
            sc=C_CRIT if 'DROP' in sig or 'Spamhaus' in sig else C_WARN if 'CINS' in sig else C_INFO
            self._s(scr,row,x+6+bw+1,sig[:sw],curses.color_pair(sc))

    def _draw_detail(self,scr,h,w):
        vis=list(self.alerts);idx=self.scrolls[0]
        if not vis or idx>=len(vis): return
        a=vis[idx];pw=min(72,w-4);ph=13;px=(w-pw)//2;py=(h-ph)//2
        dc=curses.color_pair(C_DETAIL);ba=curses.color_pair(C_OK)
        for row in range(py,py+ph): self._s(scr,row,px,' '*pw,dc)
        self._s(scr,py,px,BOX_TL+BOX_H*(pw-2)+BOX_TR,ba)
        self._s(scr,py+ph-1,px,BOX_BL+BOX_H*(pw-2)+BOX_BR,ba)
        for row in range(py+1,py+ph-1):
            self._s(scr,row,px,BOX_V,ba);self._s(scr,row,px+pw-1,BOX_V,ba)
        self._s(scr,py,px+2,' ALERT DETAIL [d=close] ',curses.color_pair(C_TITLE)|curses.A_BOLD)
        iw=pw-4
        lines=[('Time',a['time']),('Src',f"{a['src_ip']}:{a.get('src_port','')}"),('Dst',f"{a.get('dst_ip','')}:{a['dst_port']}"),('Proto',a['proto']),('Sev',f"{a['severity']} ({self.sev_name.get(a['severity'],'?')})"),('SID',str(a['sig_id'])),('Sig',a['sig_msg'][:iw-6]),('Cat',a.get('category','')[:iw-6]),('HTTP',f"{a.get('http_host','')} {a.get('http_url','')}"[:iw-7]),('UA',a.get('http_ua','')[:iw-5])]
        for i,(lbl,val) in enumerate(lines):
            if i>=ph-3: break
            row=py+1+i
            self._s(scr,row,px+2,f"{lbl}:",curses.color_pair(C_LABEL))
            self._s(scr,row,px+2+len(lbl)+1,val[:iw-len(lbl)-1],dc|curses.A_BOLD)

def main():
    term=os.environ.get('TERM','')
    if '256color' not in term and term in('xterm','screen','tmux','rxvt','linux'):
        os.environ['TERM']=term+'-256color'
    app=SuriTop()
    try: curses.wrapper(app.draw)
    except KeyboardInterrupt: pass

if __name__=='__main__': main()