Snort学习
====================

#####git 提交
		git add file1.txt
		git add file2.txt file3.txt
		git commit -m "message"
		git push origin master向远端推送修改

#####git 删除文件
		没有通过git删除：
		确实想删的话： git rm 文件名
		恢复： git checkout -- 文件名

***

#####进度
1. http://www.tuicool.com/articles/BRjmmqM 实验 snort安装配置与规则编写
晚上看看这个`(Finish,2016/4/20)`


2. 思路(2016/4/22)：
 * 打印出包解码器之后的数据包，看看有没有解码实时数据
 * 在预处理器中处理
