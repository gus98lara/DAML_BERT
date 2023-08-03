#!/bin/bash

downloaded_dataset=$1


if [ "$downloaded_dataset" = "Thunderbird" ]; then
    file="${HOME}/.dataset/tbird/"
    if [ -e $file ]
    then
      echo "INFO: $file exists"
    else
      mkdir -p $file
    fi
    echo "INFO: Downloading $downloaded_dataset dataset"
    cd $file
    zipfile=tbird2.gz
    wget http://0b4af6cdc2f0c5998459-c0245c5c937c5dedcca3f1764ecc9b2f.r43.cf2.rackcdn.com/hpc4/${zipfile}
    gunzip -k $zipfile
    cp tbird2 Thunderbird.log
    
elif [ "$downloaded_dataset" = "OpenStack" ]; then
    file=".data/OpenStack/"
    if [ -e $file ]
    then
      echo "INFO: $file exists"
    else
      mkdir -p $file
    fi
    echo "INFO: Downloading $downloaded_dataset dataset"
    cd $file
    zipfile=OpenStack.tar.gz
    wget https://zenodo.org/record/3227177/files/${zipfile}?download=1
    mv ${zipfile}?download=1 ${zipfile}
    tar -xvzf $zipfile
    
elif [ "$downloaded_dataset" == "Hadoop" ]; then
    echo "TBI"
else
    echo "ERROR: Dataset not supported"
    return 1
fi

return 0