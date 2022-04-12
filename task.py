import subprocess
import re
from ipwhois import IPWhois


regex = re.compile("(\d{1,3}\.){3}\d{1,3}")


def ip_is_local(ip):
    for localMusk in ["10.", "100.64.", "172.16.", "192.168."]:
        if ip.startswith(localMusk):
            return True
    return False


def trace(proc):
    counter = 0
    ip_before_path = True
    yield "№", "ip", "Country", "ASN"

    while True:
        raw_line = proc.stdout.readline()
        if not raw_line:
            break
        if raw_line.strip() == "":
            continue

        line = raw_line.strip().decode('cp866')
        search_res = regex.search(line)
        if search_res is None:
            continue
        if ip_before_path:
            ip_before_path = False
            continue

        counter += 1
        (start, end) = search_res.regs[0]
        ip = line[start:end]
        if ip_is_local(ip):
            yield counter, ip, "-", "-"
            continue

        info = IPWhois(ip).lookup_whois(ip)
        yield counter, ip, info.get('asn_country_code'), info.get('asn')


def run(ip_or_domain_name, process_router):
    proc = subprocess.Popen("tracert -d %s" % ip_or_domain_name,
                            shell=True,
                            stdout=subprocess.PIPE)
    line = proc.stdout.readline().strip().decode('cp866')
    if line != "":
        process_router(line)
    else:
        for num, ip, country, asn in trace(proc):
            process_router(f'{str(num):<3}{ip:<16}{country:<8}{asn}')
    proc.wait()


if __name__ == '__main__':
    run(input("Введите доменное имя или ip: "), print)
