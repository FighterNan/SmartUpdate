#! /usr/bin/python

import sys


def classify(rules, trace):
    #print 'trace', trace
    for i in xrange(0, len(rules)):
        #print 'rules[%d]' % i, rules[i]
        match = 1
        for j in xrange(0, 5):
            if trace[j] < rules[i][2*j] or trace[j] > rules[i][2*j+1]:
                match = 0
                break
        if match:
            if i + 1 is not trace[5]:
                return i + 1
            else:
                return -1


def update_match_rule_id(s_rules, s_traces):
    rules = []
    traces = []
    for s_r in s_rules:
        rule = s_r.split(' ')
        # src ip
        src_ip_r = rule[0][1:].split('/')
        src_ip_s = src_ip_r[0].split('.')
        src_ip = int(src_ip_s[0]) << 24 | int(src_ip_s[1]) << 16 | int(src_ip_s[2]) << 8 | int(src_ip_s[3])
        src_ip_1 = src_ip & ~((1 << (32 - int(src_ip_r[1]))) - 1)
        src_ip_2 = src_ip | ((1 << (32 - int(src_ip_r[1]))) - 1)
        # dst ip
        dst_ip_r = rule[1].split('/')
        dst_ip_s = dst_ip_r[0].split('.')
        dst_ip = int(dst_ip_s[0]) << 24 | int(dst_ip_s[1]) << 16 | int(dst_ip_s[2]) << 8 | int(dst_ip_s[3])
        dst_ip_1 = dst_ip & ~((1 << (32 - int(dst_ip_r[1]))) - 1)
        dst_ip_2 = dst_ip | ((1 << (32 - int(dst_ip_r[1]))) - 1)
        # src port
        src_port_1 = int(rule[2])
        src_port_2 = int(rule[4])
        # dst port
        dst_port_1 = int(rule[5])
        dst_port_2 = int(rule[7])
        # protocol
        protocol_r = rule[8].split('/')
        if protocol_r[1] is '0xff':
            protocol_1 = int(protocol_r[0], 0)
            protocol_2 = int(protocol_r[0], 0)
        else:
            protocol_1 = 0
            protocol_2 = 255
        rules.append([src_ip_1, src_ip_2, dst_ip_1, dst_ip_2, src_port_1, src_port_2, dst_port_1, dst_port_2, protocol_1, protocol_2])
    for i in xrange(0, len(s_traces)):
        r_id = classify(rules, (map(int, s_traces[i].split(' '))))
        if r_id is -1:
            continue
        s_ts = s_traces[i].split(' ')[:-1]
        new_s_t = ''
        for j in s_ts:
            new_s_t += j + ' '
        new_s_t += str(r_id)
        s_traces[i] = new_s_t


def main():
    rules = []
    traces = []

    with open('%s' % sys.argv[1]) as fi:
        for i in fi.readlines():
            rules.append(i[:-1])

    with open('%s' % sys.argv[2]) as fi:
        for i in fi.readlines():
            traces.append(i[:-1])

    update_match_rule_id(rules, traces)

    with open('%s' % sys.argv[2], 'w') as fo:
        for i in traces:
            fo.write('%s\n' % i)


if __name__ == "__main__":
    main()
