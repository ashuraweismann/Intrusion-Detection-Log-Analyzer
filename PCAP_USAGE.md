# PCAP Conversion

This project now includes a helper script that converts a classic `.pcap` file
into the same `logs.txt` format used by the C++ intrusion detection program.

## Command

```bash
python pcap_to_logs.py sample.pcap -o logs.txt
```

## Guaranteed Demo Capture

If you want a local sample that is safe and guaranteed to trigger all output
types used by the current converter, generate one with:

```bash
python generate_demo_pcap.py
python pcap_to_logs.py demo_all_cases.pcap -o logs.txt
```

With the default settings, the generated file contains traffic that produces rows like:

```text
192.168.1.50 22 20 FAILED_LOGIN 1714464000
10.10.10.20 80 5 PORT_SCAN 1714464101
172.16.0.30 53 10 NORMAL 1714464200
192.168.1.60 23 20 FAILED_LOGIN 1714467600
10.20.10.20 81 5 PORT_SCAN 1714467701
172.16.1.30 5353 10 NORMAL 1714467800
```

That default all-in-one file now contains 100 packets total:

- 40 packets for `FAILED_LOGIN`
- 40 packets for `PORT_SCAN`
- 20 packets for `NORMAL`

It also contains two different time windows, so the delete-by-date-time feature is easier to demo.

If you want the smaller single-purpose file from before, you can still use:

```bash
python generate_demo_pcap.py --profile failed-login-only -o demo_failed_login.pcap
python pcap_to_logs.py demo_failed_login.pcap -o logs.txt
```

## Output Format

Each generated line looks like this:

```text
source_ip destination_port attempt_count attack_type timestamp
```

Example:

```text
192.168.1.10 22 6 FAILED_LOGIN
192.168.1.10 21 1 PORT_SCAN
10.0.0.5 80 3 NORMAL
```

## Detection Heuristics

The converter uses simple rules that match your current C++ logic:

- Repeated TCP SYN packets to login-related ports can be labeled `FAILED_LOGIN`.
- A source IP that touches many unique destination ports can be labeled `PORT_SCAN`.
- Other traffic is labeled `NORMAL`.

## Optional Thresholds

```bash
python pcap_to_logs.py sample.pcap -o logs.txt --port-scan-threshold 5 --failed-login-threshold 6
```

## Current Limitation

This script supports classic `.pcap` files. It does not parse `.pcapng` yet.
