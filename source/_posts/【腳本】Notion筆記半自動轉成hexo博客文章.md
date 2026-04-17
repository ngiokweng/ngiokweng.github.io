---
title: 【腳本】Notion筆記半自動轉成hexo博客文章
date: 2024-05-09 20:11:09
tags:
- Script
categories: Script
keywords:
- Notion
- hexo Blog
- Script
description: Notion筆記半自動轉成hexo Blog的格式
cover: Untitled.png
---

Notion自帶導出功能：

![Untitled](Untitled.png)

導出的壓縮包裡，一個是md格式的notion筆記，一個是保存圖片的資料夾，如下所示：

![Untitled](Untitled1.png)

在腳本同級目錄下創建一個`target`目錄，將壓縮包裡的東西放進去。

手動配置blogInfo，然後執行腳本即可

![Untitled](Untitled2.png)

腳本如下：

```python
import os
import re
from datetime import datetime

def removeSpaces(directory):
    for filename in os.listdir(directory):
        newFilename = filename.replace(" ", "")
        if newFilename != filename:
            oldPath = os.path.join(directory, filename)
            newPath = os.path.join(directory, newFilename)
            os.rename(oldPath, newPath)

"""
---
title: ACTF新生赛2020-usualCrypt WriteUp
date: 2022-02-23 19:23:48
tags: 
	- Reverse
	- WriteUp
categories: CTF
keywords:
    - CTF
    - Buuctf
    - 逆向
    - ACTF新生赛2020
    - usualCrypt
    - WriteUp
description: buuctf的ACTF新生赛2020-usualCrypt的WriteUp
cover: hack.jpg
---
"""

blogInfo = {
    "title": "殼實現的基本原理",
    "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "tags": ["Android逆向"],
    "categories": "Android逆向",
    "keywords": ["Android逆向", "Android加殼", "修復ClassLoader", "修復Application"],
    "description": "殼實現的基本原理",
    "cover": "Untitled.png"
}

def makeFirstLine():
    res = "---\n"
    res += ("title: " + blogInfo["title"] + '\n')
    res += ("date: " + blogInfo["date"] + '\n')
    res += ("tags:\n")
    for tag in blogInfo["tags"]:
        res += ("- " + tag + '\n')
    res += ("categories: " + blogInfo["categories"] + '\n')

    res += ("keywords:\n")
    for keyword in blogInfo["keywords"]:
        res += ("- " + keyword + '\n')

    res += ("description: " + blogInfo["description"] + '\n')
    res += ("cover: " + blogInfo["cover"] + '\n')
    res += '---\n'

    print(res)
    return res

def removeFirstLine(path):
    with open(path, mode="r", encoding="utf-8") as file:
        lines = file.readlines()

    # 刪除第一行
    lines = lines[1:]

    with open(path, mode="w", encoding="utf-8") as file:
        file.writelines(lines)

if __name__ == "__main__":
    basePath = "./target"
    fileNames = os.listdir(basePath)
    for fileName in fileNames:
        if fileName.endswith(".md"):
            os.rename(f"{basePath}/{fileName}", f"{basePath}/{blogInfo['title']}.md")
        else:
            os.rename(f"{basePath}/{fileName}", f"{basePath}/{blogInfo['title']}")
    
    folderPath = f"{basePath}/{blogInfo['title']}"
    blogMdPath = f"{basePath}/{blogInfo['title']}.md"

    
    removeFirstLine(blogMdPath)

    with open(blogMdPath, mode="r", encoding="utf-8") as f:
        tmp = f.read()
    

    idx = 0
    targetImgLinks = re.findall(r"!\[.*?\]\(.*?/Untitled.*?\.png\)", tmp)
    for targetImgLink in targetImgLinks:
        if idx == 0:
            tmp = tmp.replace(targetImgLink, "![Untitled](Untitled.png)")
        else:
            tmp = tmp.replace(targetImgLink, f"![Untitled](Untitled{idx}.png)")
        idx += 1

    tmp = makeFirstLine() + tmp

    with open(blogMdPath, mode="w", encoding="utf-8") as f:
        f.write(tmp)

    removeSpaces(folderPath)
```