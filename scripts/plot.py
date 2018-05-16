#! /usr/bin/python

import numpy as np
import matplotlib.pyplot as plt

tss = (26, 58, 80, 172, 220, 221)
hicts = (51, 50, 45, 53, 49, 37)
hs = (13, 20, 23, 17, 25, 34)

n_groups = 6

index = np.arange(n_groups)

bar_width = 0.2
opacity   = 0.3

f = plt.figure()

rects1 = plt.bar(index, tss, bar_width, alpha = opacity, color='r', label = 'TSS')
rects2 = plt.bar(index + bar_width, hicts, bar_width, alpha = opacity, color='g', label = 'HiCuts')
rects3 = plt.bar(index + 2 * bar_width, hs, bar_width, alpha = opacity, color='b', label = 'HyperSplit')

plt.xlabel('Rule Set')
plt.ylabel('Memory Access')
plt.gca().yaxis.grid(True)

plt.xticks(index - 0.2 + 2 * bar_width, ['acl1_100', 'acl1_1K', 'acl1_10K', 'fw1_100', 'fw1_1K', 'fw1_10K'])
plt.legend(loc=2, prop={'size': 10})

plt.xlim(-0.5, 6)
plt.ylim(0, 250)

plt.show()

f.savefig('result.png', bbox_inches='tight')
