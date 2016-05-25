#####进度记录
1. http://www.tuicool.com/articles/BRjmmqM 实验 snort安装配置与规则编写
晚上看看这个`(Finish,2016/4/20)`


2. 思路(2016/4/22)：
 * 打印出包解码器之后的数据包，看看有没有解码实时数据`(Finish,2016/05/18) 解决了存储和打印实时报文`
 * 在预处理器中处理

3. libcap使用 http://blog.csdn.net/htttw/article/details/7521053 `Finish 2016/05/03`

4. 修改检测引擎似乎太麻烦、、不仅仅是修改一个 alert 后面对应的协议名字那么简单。 

5. http://www.cppblog.com/iniwf/archive/2012/05/18/77468.html 这个源码分析  参考一下，提到说协议类型判断TCP/UDP/ICMP之外的都判断为IP，似乎可从这里入手.（2016/05/19）  `不行`

6. IDS模式下经常会Segmentation fault (core dumped)，位置在snort.c 1919行左右 Preprocess()函数返回之前  `忽略他`

7. http://drops.wooyun.org/%E8%BF%90%E7%BB%B4%E5%AE%89%E5%85%A8/9232 一个很好的参考链接

8. IDS Informer模拟发包
	
9. 先在preprocessor中写出来几条简单的入侵检测规则，然后再研究一下在preprocessor中报警。报警这个可以使用别的预处理器的报警id，改变一下输出内容