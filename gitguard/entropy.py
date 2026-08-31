import math
from collections import Counter


def calculate_entropy(value: str)->float:

    if not value:
        return 0.0


    counts = Counter(value)
    length=len(value)


    entropy=0.0

    for count in counts.values():
        probability=count/length
        entropy-=probability*math.log2(probability)


    return entropy
