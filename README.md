# usage:

## 列出 tcp 会话
```
pcapparse test.pcap -t tcp
```


## 生成 tcp infligth 图
```
pcapparse test.pcap -t tcp-flight --draw-source 127.0.0.1:80 --draw-output flight.png
```


# TODO
* change the Stream of StreamBuf to pipe
* feature: draw Stevens plot
