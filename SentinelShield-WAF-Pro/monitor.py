import psutil
from datetime import datetime

def system_snapshot():
    vm=psutil.virtual_memory()
    disk=psutil.disk_usage("/")
    return {
        "timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "cpu_percent":psutil.cpu_percent(interval=0.1),
        "memory_percent":vm.percent,
        "memory_used_mb":round(vm.used/1024/1024),
        "memory_total_mb":round(vm.total/1024/1024),
        "disk_percent":disk.percent,
        "process_count":len(psutil.pids())
    }

def process_snapshot(limit=15):
    rows=[]
    for p in psutil.process_iter(["pid","name","username","cpu_percent","memory_percent"]):
        try:
            info=p.info
            rows.append({
                "pid":info["pid"],"name":info["name"] or "Unknown",
                "username":info["username"] or "Unknown",
                "cpu_percent":round(info["cpu_percent"] or 0,1),
                "memory_percent":round(info["memory_percent"] or 0,1)
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return sorted(rows,key=lambda x:(x["cpu_percent"],x["memory_percent"]),reverse=True)[:limit]
