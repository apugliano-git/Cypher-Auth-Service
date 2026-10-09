#!/usr/bin/env python3
"""Bounded synthetic HTTP load; invoked only by the ephemeral JUnit fixture."""
import argparse, concurrent.futures, http.client, json, math, os, time
from pathlib import Path
from urllib.parse import urlparse

def percentile(values, p):
    values = sorted(values)
    return round(values[max(0, math.ceil(len(values)*p)-1)], 3)

def summaries(samples, phases):
    results=[]
    for phase in phases:
        for operation in ["login_valid","login_invalid","register","refresh"]:
            rows=[row for row in samples if row["phase"]==phase and row["operation"]==operation]
            latency=[row["ms"] for row in rows]
            statuses={str(status):sum(r["status"]==status for r in rows) for status in sorted(set(r["status"] for r in rows))}
            admitted=[r["ms"] for r in rows if r["status"] in [200,201,401]]
            results.append({"phase":phase,"operation":operation,"attempts":len(rows),"statuses":statuses,"p50_ms":percentile(latency,.5),"p95_ms":percentile(latency,.95),"p99_ms":percentile(latency,.99),"admitted_p95_ms":percentile(admitted,.95) if admitted else None})
    return results

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True); parser.add_argument("--fixture-pid", required=True, type=int)
    parser.add_argument("--output", required=True); parser.add_argument("--sustained", action="store_true"); args = parser.parse_args()
    url = urlparse(args.url)
    assert url.hostname == "127.0.0.1" and url.port and url.scheme == "http", "Ephemeral loopback only"
    assert Path(f"/proc/{args.fixture_pid}").exists(), "Fixture JVM must exist"
    mem = dict(line.split(":",1) for line in Path("/proc/meminfo").read_text().splitlines())
    assert int(mem["MemAvailable"].split()[0]) > 2*1024*1024, "Stop below 2 GiB available"
    samples=[]; resources=[]; start=time.monotonic(); failures=0; unexpected=[]
    def request(path, body, source, operation, phase):
        nonlocal failures
        before=time.monotonic(); status=0; result={}
        try:
            connection=http.client.HTTPConnection(url.hostname,url.port,timeout=5,source_address=(f"127.0.0.{source}",0))
            connection.request("POST",path,json.dumps(body),{"Content-Type":"application/json"})
            response=connection.getresponse(); status=response.status; raw=response.read(32768); connection.close()
            if status==200: result=json.loads(raw)
        except (OSError,ValueError): status=0
        duration=1000*(time.monotonic()-before)
        samples.append({"phase":phase,"operation":operation,"status":status,"ms":round(duration,3)})
        allowed={"login_valid":{200,429},"login_invalid":{401,429},"register":{201,429},"refresh":{200,429}}[operation]
        if status not in allowed:
            failures+=1; unexpected.append({"phase":phase,"operation":operation,"status":status})
        return status,result
    password="SyntheticPassword123!"
    if args.sustained:
        ticks_per_second=os.sysconf("SC_CLK_TCK")
        previous_cpu=0; previous_time=start
        def sample_resource(phase):
            nonlocal previous_cpu,previous_time
            now=time.monotonic()
            stat=Path(f"/proc/{args.fixture_pid}/stat").read_text().split()
            ticks=int(stat[13])+int(stat[14])
            rss=int(Path(f"/proc/{args.fixture_pid}/status").read_text().split("VmRSS:")[1].split()[0])
            available=int(next(line for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:")).split()[1])
            resources.append({"phase":phase,"elapsed_seconds":round(now-start,3),"jvm_rss_kib":rss,"available_kib":available,
                "jvm_cpu_percent":round((ticks-previous_cpu)/ticks_per_second/(now-previous_time)*100,2) if previous_cpu else None})
            previous_cpu=ticks; previous_time=now
            assert rss < 2*1024*1024 and available > 2*1024*1024, "Sustained resource stop threshold"
            assert now-start < 210, "Sustained wall budget exceeded"
        sample_resource("before")
        measurement_start=time.monotonic()
        for cycle in range(60):
            time.sleep(max(0,measurement_start+cycle*3-time.monotonic()))
            phase=f"minute-{cycle//20+1}"; source=cycle+1; email=f"sustained-{cycle}@example.com"
            assert request("/auth/register",{"email":email,"password":password},source,"register",phase)[0]==201
            status,pair=request("/auth/login",{"email":email,"password":password},source,"login_valid",phase)
            assert status==200
            assert request("/auth/login",{"email":email,"password":"incorrect"},source,"login_invalid",phase)[0]==401
            assert request("/auth/refresh",{"refresh_token":pair["refresh_token"]},source,"refresh",phase)[0]==200
            sample_resource(phase)
            assert failures==0, "Unexpected sustained response"
        time.sleep(max(0,measurement_start+180-time.monotonic()))
        measurement_seconds=time.monotonic()-measurement_start
        sample_resource("end")
        time.sleep(5)
        assert request("/auth/register",{"email":"sustained-recovery@example.com","password":password},100,"register","recovery")[0]==201
        assert request("/auth/login",{"email":"sustained-recovery@example.com","password":password},100,"login_valid","recovery")[0]==200
        sample_resource("recovery")
        results=summaries(samples,["minute-1","minute-2","minute-3"])
        output={"mode":"sustained", "budget":{"measurement_seconds":180,"max_seconds":210,"concurrency":1,"cycle_interval_seconds":3,
            "http_timeout_seconds":5,"min_available_mib":2048,"max_jvm_rss_mib":2048,"admitted_p95_max_ms":1000,"stop_on_unexpected_response":True},
            "configuration":{"rate_limit":5,"window_minutes":5,"refresh_ip_limit":30,"limits_active":True,"sources":"127.0.0.1..60; recovery .100","llm":"disabled","jvm_pid":args.fixture_pid},
            "measurement_seconds":round(measurement_seconds,3),"measured_attempts":240,"admitted_attempts":sum(r["status"] in (200,201,401) for r in samples if r["phase"]!='recovery'),
            "throughput_rps":round(240/measurement_seconds,3),"results":results,"resources":resources,"samples":samples,
            "unexpected_count":failures,"server_errors_or_timeouts":sum(r["status"]==0 or r["status"]>=500 for r in samples),"wall_seconds":round(time.monotonic()-start,3)}
        Path(args.output).write_text(json.dumps(output,indent=2)+"\n")
        assert len(samples)==242 and output["admitted_attempts"]==240 and failures==0
        assert all(r["admitted_p95_ms"] < 1000 for r in results), "Sustained admitted latency criterion failed"
        return
    # Setup is recorded separately; 32 independent source addresses and identities.
    tokens={}
    for i in range(1,33):
        email=f"load-{i}@example.com"
        assert request("/auth/register",{"email":email,"password":password},i,"register","setup")[0]==201
        status,pair=request("/auth/login",{"email":email,"password":password},i,"login_valid","setup")
        assert status==200; tokens[i]=pair["refresh_token"]
    def job(index,phase):
        source=index%32+1; operation=["login_valid","login_invalid","register","refresh"][index%4]
        email=f"load-{source}@example.com"
        if operation.startswith("login"):
            return request("/auth/login",{"email":email,"password":password if operation=="login_valid" else "incorrect"},source,operation,phase)
        if operation=="register":
            return request("/auth/register",{"email":f"new-{phase}-{index}@example.com","password":password},source,operation,phase)
        status,pair=request("/auth/refresh",{"refresh_token":tokens[source]},source,operation,phase)
        if status==200:tokens[source]=pair["refresh_token"]
        return status,pair
    stat=Path(f"/proc/{args.fixture_pid}/stat").read_text().split()
    previous_cpu=int(stat[13])+int(stat[14]); ticks_per_second=os.sysconf("SC_CLK_TCK")
    phases=[]
    # Baseline and steps carry existing rate counters forward; no flush/reset/diagnostic limits.
    for name,concurrency,count in [("baseline",1,16),("step-2",2,32),("step-4",4,48),("spike",8,64)]:
        before=time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            list(pool.map(lambda index:job(index,name),range(count)))
        seconds=time.monotonic()-before
        stat=Path(f"/proc/{args.fixture_pid}/stat").read_text().split()
        rss=int(Path(f"/proc/{args.fixture_pid}/status").read_text().split("VmRSS:")[1].split()[0])
        cpu_ticks=int(stat[13])+int(stat[14])
        resources.append({"phase":name,"jvm_rss_kib":rss,"jvm_cpu_ticks":cpu_ticks,"jvm_cpu_percent":round((cpu_ticks-previous_cpu)/ticks_per_second/seconds*100,2)})
        previous_cpu=cpu_ticks
        assert rss < 2*1024*1024, "Stop: JVM RSS exceeds 2 GiB"
        available=int(next(line for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:")).split()[1])
        assert available > 2*1024*1024, "Stop: available memory below 2 GiB"
        assert failures<=2, "Stop: more than two server errors/timeouts"
        assert time.monotonic()-start<60, "Campaign wall budget exceeded"
        phases.append({"phase":name,"concurrency":concurrency,"attempts":count,"seconds":round(seconds,3),"throughput_rps":round(count/seconds,3)})
        time.sleep(.25)
    # Recovery uses a new synthetic IP/identity, keeping all limits active.
    assert request("/auth/register",{"email":"recovery@example.com","password":password},100,"register","recovery")[0]==201
    assert request("/auth/login",{"email":"recovery@example.com","password":password},100,"login_valid","recovery")[0]==200
    results=summaries(samples,[p["phase"] for p in phases])
    output={"budget":{"max_concurrency":8,"max_seconds":60,"http_timeout_seconds":5,"min_available_mib":2048,"max_jvm_rss_mib":2048,"stop_after_server_errors":2},"configuration":{"rate_limit":5,"window_minutes":5,"refresh_ip_limit":30,"limits_active":True,"sources":"127.0.0.1..32; recovery .100","llm":"disabled","jvm_pid":args.fixture_pid},"phases":phases,"results":results,"resources":resources,"samples":samples,"unexpected_responses":unexpected,"unexpected_count":failures,"server_errors_or_timeouts":sum(r["status"]==0 or r["status"]>=500 for r in samples),"wall_seconds":round(time.monotonic()-start,3)}
    Path(args.output).write_text(json.dumps(output,indent=2)+"\n")
    assert failures==0, "Server errors/timeouts prevent PASS"

if __name__=="__main__":main()
