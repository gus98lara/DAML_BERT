import sys
sys.path.append('../')
sys.path.append('./')

import os
import pandas as pd
import numpy as np
from logparser import Spell, Drain
from tqdm import tqdm
from logdeep.dataset.session import sliding_window

tqdm.pandas()
pd.options.mode.chained_assignment = None  # default='warn'

abnormal_labels = [
    "544fd51c-4edc-4780-baae-ba1d80a0acfc",
    "ae651dff-c7ad-43d6-ac96-bbcd820ccca8",
    "a445709b-6ad0-40ec-8860-bec60b6ca0c2",
    "1643649d-2f42-4303-bfcd-7798baec19f9"
]

def deeplog_file_generator(filename, df, features):
    with open(filename, 'w') as f:
        for _, row in df.iterrows():
            for val in zip(*row[features]):
                f.write(','.join([str(v) for v in val]) + ' ')
            f.write('\n')


def parse_log(input_dir, output_dir, log_file, parser_type):
    log_format = '<Logrecord> <Date> <Time> <Pid> <Level> <Component> \[<ADDR>\] <Content>'
    regex = [
        r'((\d+\.){3}\d+,?)+', r'/.+?\s', r'\d+'
    ]
    keep_para = False
    if parser_type == "drain":
        # the hyper parameter is set according to http://jmzhu.logpai.com/pub/pjhe_icws2017.pdf
        st = 0.5  # Similarity threshold
        depth = 5  # Depth of all leaf nodes

        # Drain is modified
        parser = Drain.LogParser(log_format,
                                 indir=input_dir,
                                 outdir=output_dir,
                                 depth=depth,
                                 st=st,
                                 rex=regex,
                                 keep_para=keep_para, maxChild=1000)
        parser.parse(log_file)

    elif parser_type == "spell":
        tau = 0.35
        parser = Spell.LogParser(indir=data_dir,
                                 outdir=output_dir,
                                 log_format=log_format,
                                 tau=tau,
                                 rex=regex,
                                 keep_para=keep_para)
        parser.parse(log_file)



def sample_raw_data(data_file, output_file, sample_window_size, sample_step_size):
    # sample 1M by sliding window, abnormal rate is over 2%
    sample_data = []
    labels = []
    idx = 0

    # spirit dataset can start from the 2Mth line, as there are many abnormal lines gathering in the first 2M
    
    with open(data_file, 'r', errors='ignore') as f:
        for line in f:
            labels.append(any(element in line for element in abnormal_labels))
            sample_data.append(line)

            if len(labels) == sample_window_size:
                abnormal_rate = sum(np.array(labels)) / len(labels)
                print(f"{idx + 1} lines, abnormal rate {abnormal_rate}")
                break

            idx += 1
            if idx % sample_step_size == 0:
                print(f"Process {round(idx/sample_window_size * 100,4)} % raw data", end='\r')

    with open(output_file, "w") as f:
        f.writelines(sample_data)

    print("Sampling done")

def merge_files(filenames, data_dir):
    with open(os.path.join(data_dir ,'OpenStack.log'), 'w') as outfile:
        for names in filenames:
            with open(names) as infile:
                outfile.write(infile.read())
            outfile.write("\n")

if __name__ == "__main__":
    data_dir = os.path.expanduser("~/.dataset/OpenStack/")
    output_dir = "../output/OpenStack/"
    raw_log_file = "OpenStack.log"
    sample_log_file = "OpenStack_20M.log"
    sample_window_size = 2*10**7
    sample_step_size = 10**4
    window_name = ''
    log_file = sample_log_file
    merge_files([os.path.join(data_dir, "openstack_abnormal.log"), os.path.join(data_dir, "openstack_normal1.log") ], data_dir)
    parser_type = 'drain'
    #mins
    window_size = 1
    step_size = 0.5
    train_ratio = 6000

    ########
    # count anomaly
    ########
    # count_anomaly(data_dir + log_file)
    # sys.exit()

    #########
    # sample raw data
    #########
    sample_raw_data(data_dir+raw_log_file, data_dir+sample_log_file, sample_window_size, sample_step_size )


    ##########
    # Parser #
    #########
    parse_log(data_dir, output_dir, log_file, parser_type)

    ##################
    # Transformation #
    ##################
    df = pd.read_csv(f'{output_dir}{log_file}_structured.csv')

    # data preprocess
    df["Label"] = df["Label"].apply(lambda x: int(x != "-"))

    df['datetime'] = pd.to_datetime(df["Date"] + " " + df['Time'], format='%Y-%m-%d %H:%M:%S')
    df['timestamp'] = df["datetime"].values.astype(np.int64) // 10 ** 9
    df['deltaT'] = df['datetime'].diff() / np.timedelta64(1, 's')
    df['deltaT'].fillna(0)

    # sampling with sliding window
    #deeplog_df = sliding_window(df[["timestamp", "Label", "EventId", "deltaT"]],
    #                            para={"window_size": float(window_size)*60, "step_size": float(step_size) * 60}
    #                            )
    #output_dir += window_name
    #
    ##########
    ## Train #
    ##########
    #df_normal = deeplog_df[deeplog_df["Label"] == 0]
    #df_normal = df_normal.sample(frac=1, random_state=12).reset_index(drop=True) #shuffle
    #normal_len = len(df_normal)
    #train_len = int(train_ratio) if train_ratio >= 1 else int(normal_len * train_ratio)
    #
    #train = df_normal[:train_len]
    #deeplog_file_generator(os.path.join(output_dir,'train'), train, ["EventId"])
    #print("training size {}".format(train_len))
    #
    #
    ################
    ## Test Normal #
    ################
    #test_normal = df_normal[train_len:]
    #deeplog_file_generator(os.path.join(output_dir, 'test_normal'), test_normal, ["EventId"])
    #print("test normal size {}".format(normal_len - train_len))


    ##################
    ## Test Abnormal #
    ##################
    #df_abnormal = deeplog_df[deeplog_df["Label"] == 1]
    #deeplog_file_generator(os.path.join(output_dir,'test_abnormal'), df_abnormal, ["EventId"])
    #print('test abnormal size {}'.format(len(df_abnormal)))

