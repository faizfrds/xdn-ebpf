import numpy as np
from datetime import datetime
import statistics

def parse_time(time_str):
    time_str = time_str.strip().replace('s','') #removing the s in time
    
    minutes, seconds = time_str.split('m') #splitting at m
    total_seconds = float(minutes)*60 + float(seconds)

    return total_seconds

    #time_format = datetime.strptime(time_str, '%S.%f')
    #return time_format

def extract(filename):
    time_store = []
    file = open(filename, 'r')
    Lines = file.readlines()

    for line in Lines:
        time_store.append(parse_time(line))

    return calculate(time_store)



def calculate(times):
    times.sort()
    mid = len(times) // 2
    median = statistics.median(times)
    mean = statistics.mean(times)
    p = np.percentile(np.array(times), 95)

    print("mean: {mean:.6f}s, median: {median:.6f}s, p95: {p:.6f}s".format(mean = mean, median = median, p = p)) 

filename = "times.txt"
extract(filename)


