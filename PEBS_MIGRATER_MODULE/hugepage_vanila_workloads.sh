#bin/sh





echo 3 | sudo tee /proc/sys/vm/drop_caches

/usr/bin/time -v /home/hjcho/benchmark/liblinear-multicore-2.47/train -s 6 -m 15 /home/hjcho/benchmark/liblinear-multicore-2.47/datasets/kdd12 >> PEBS_base 2>>PEBS_base &

PID=$(ps aux | grep '/home/hjcho/benchmark/liblinear-multicore-2.47/train' | grep -v grep | awk 'NR==2 {print $2}')

sudo insmod /home/hjcho/pebs/pebs_migrater.ko target_pid=$PID

while kill -0 $PID 2>/dev/null; do
    # PID가 살아 있는 동안 기다림
    sleep 5
done

sudo rmmod pebs_migrater

dmesg | tail -20 >> PEBS_result

echo 3 | sudo tee /proc/sys/vm/drop_caches

/usr/bin/time -v /home/hjcho/benchmark/liblinear-multicore-2.47/train -s 6 -m 15 /home/hjcho/benchmark/liblinear-multicore-2.47/datasets/kdd12 >> PEBS_base 2>>PEBS_base &

PID=$(ps aux | grep '/home/hjcho/benchmark/liblinear-multicore-2.47/train' | grep -v grep | awk 'NR==2 {print $2}')

sudo insmod /home/hjcho/pebs/pebs_migrater.ko target_pid=$PID

while kill -0 $PID 2>/dev/null; do
    # PID가 살아 있는 동안 기다림
    sleep 5
done

sudo rmmod pebs_migrater

dmesg | tail -20 >> PEBS_result

echo 3 | sudo tee /proc/sys/vm/drop_caches

/usr/bin/time -v /home/hjcho/benchmark/liblinear-multicore-2.47/train -s 6 -m 15 /home/hjcho/benchmark/liblinear-multicore-2.47/datasets/kdd12 >> PEBS_base 2>>PEBS_base &

PID=$(ps aux | grep '/home/hjcho/benchmark/liblinear-multicore-2.47/train' | grep -v grep | awk 'NR==2 {print $2}')

sudo insmod /home/hjcho/pebs/pebs_migrater.ko target_pid=$PID

while kill -0 $PID 2>/dev/null; do
    # PID가 살아 있는 동안 기다림
    sleep 5
done

sudo rmmod pebs_migrater

dmesg | tail -20 >> PEBS_result
