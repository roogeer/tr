#!/usr/bin/env python
# coding:utf8

"""
    版本：v4.0
程序功能：新增-hide参数，隐藏本地设备名称
    作者：Roger
    时间：2024年11月27日

    版本：v3.0
程序功能：新增IPv6的支持
    作者：Roger
    时间：2024年11月27日

    版本：v1.0
程序功能：新增-纯真数据库信息查询
    作者：Roger
    时间：2024年11月17日

    版本：v0.6
程序功能：新增-list ip 查询路由的功能
    作者：Roger
    时间：2024年11月15日

    版本：v0.5
程序功能：新增数据库排序
    作者：Roger
    时间：2024年11月14日
"""

from fastapi import FastAPI
from pydantic import BaseModel
import json
import IPy
from czdb.db_searcher import DbSearcher

class Item(BaseModel):
    deviceip: str
    devicename: str

class RetItem(BaseModel):
    '''
     dbinfo: 指示返回的数据是local.json(ipdb),还是纯真数据库(czdb)
     ipinfo: ip对应的信息
    '''
    dbinfo: str
    ipinfo: str

class IP_NETWORK(BaseModel):
    deviceip: str

app = FastAPI()

@app.get("/trserver/getversion/")
async def getversion():
    # 这里要去纯真数据库里查询
    database_path = "/usr/share/nginx/html/trserver/czdb/cz88_public_v4.czdb"
    query_type = "BTREE"
    key = "uK+eMTs27M0Td8b3SkUNpw=="
    ip = "255.255.255.255"

    db_searcher = DbSearcher(database_path, query_type, key)

    try:
        region = db_searcher.search(ip)
        # print("搜索结果：")
        # print(region)
        region = region.replace('\t', ':')
        return region
    except Exception as e:
        # print(f"An error occurred during the search: {e}")
        return f"An error occurred during the search: {e}"
    finally:
        db_searcher.close()

@app.get("/trserver/getnamebyip/{ip}")
async def getnamebyip(ip):
    # 准备待查的数据库
    with open("/usr/share/nginx/html/trserver/ipdb.json", "r", encoding="utf-8") as f:
        ipdb=json.load(f)

    # print(ip)
    _ip = IPy.IP(ip)

    result = {}
    for dstip, dstinfo in ipdb.items():
        dstip = IPy.IP(dstip)
        if _ip in dstip:
            result[dstinfo] = dstip.prefixlen()

    if len(result):
        resultinfo, _ = max(result.items(), key = lambda x: x[1])
        # return(resultinfo)
        return RetItem(dbinfo='ipdb', ipinfo=resultinfo)
    else:
        # 这里要去纯真数据库里查询
        # return("???")
        database_path = "/usr/share/nginx/html/trserver/czdb/cz88_public_v4.czdb"
        query_type = "BTREE"
        key = "uK+eMTs27M0Td8b3SkUNpw=="
        # ip = "192.168.108.1"

        db_searcher = DbSearcher(database_path, query_type, key)

        try:
            region = db_searcher.search(ip)
            # print("搜索结果：")
            # print(region)
            region = region.replace('\t', ' ☆ ')
            # return region
            return RetItem(dbinfo='czdb', ipinfo=region)
        except Exception as e:
            # print(f"An error occurred during the search: {e}")
            return f"An error occurred during the search: {e}"
        finally:
            db_searcher.close()        

@app.post("/trserver/updatenamebyip/")
async def updatenamebyip(item: Item):
    # print(item)
    data={item.deviceip:item.devicename}
    # 准备待查的数据库
    with open("/usr/share/nginx/html/trserver/ipdb.json", "r", encoding="utf-8") as f:
        ipdb=json.load(f)

    # 更新数据库
    ipdb.update(data)

    # 先整理ip顺序
    # sorted_ipdb = { k:ipdb[k] for k in sorted(ipdb.keys()) }
    sorted_ipdb = {k:v for k,v in sorted(ipdb.items(), key=lambda item: IPy.IP(item[0]).int())}
    # 重写数据库文件    
    with open('/usr/share/nginx/html/trserver/ipdb.json', "w", encoding="utf-8") as f:
        f.write(json.dumps(sorted_ipdb))
  
    return item

# 返回指定ipv4的信息
@app.get("/trserver/getipdb/")
async def getipdb(ip=None):
    # 准备待查的数据库
    with open("/usr/share/nginx/html/trserver/ipdb.json", "r", encoding="utf-8") as f:
        ipdb=json.load(f)

    if not ip:
        # 无查询的ip，返回全部数据
        return ipdb
    else:
        # 返回匹配指定ip的路由
        _ip = IPy.IP(ip)

        # 保存所有匹配的路由
        result = {
            "db":"",
            "ipinfo":[]
        }
        _result = []
        for dstip, dstinfo in ipdb.items():
            dstip = IPy.IP(dstip)
            if _ip in dstip:
                _result.append((dstip.prefixlen(), dstip.strNormal(), dstinfo))

        # 按最长匹配原则，从大到小排列后，返回数据
        ret = sorted([(deviceip, devicename) for (prefix, deviceip, devicename) in _result], key=lambda prefix:prefix, reverse=True)

        # 如果所查询的ip在ipdb中
        if len(ret):
            result["db"] = "ipdb"
            result["ipinfo"] = ret
            return result
        else:
            # 所查询的ip不在ipdb中，在czdb中查询
            database_path = "/usr/share/nginx/html/trserver/czdb/cz88_public_v4.czdb"
            query_type = "BTREE"
            key = "uK+eMTs27M0Td8b3SkUNpw=="

            db_searcher = DbSearcher(database_path, query_type, key)

            try:
                region = db_searcher.search(ip)
                # print("搜索结果：")
                # print(region)
                region = region.replace('\t', ' ☆ ')
                result["db"] = "czdb"
                result["ipinfo"].append((ip, region))
                return result
            except Exception as e:
                # print(f"An error occurred during the search: {e}")
                return f"An error occurred during the search: {e}"
            finally:
                db_searcher.close()


@app.post("/trserver/deletenamebyip/")
async def deletenamebyip(ip_network:IP_NETWORK):
    ip = ip_network.deviceip
    result = {"deviceip":ip, "devicename":"没有对应的信息"}

    # 准备待查的数据库
    with open("/usr/share/nginx/html/trserver/ipdb.json", "r", encoding="utf-8") as f:
        ipdb=json.load(f)

    # ipdb中是否有指定的ip标记
    ret = ipdb.get(ip)
    if ret:
        deletedinfo = ipdb.pop(ip)
        result["devicename"] = f'对应的 [{deletedinfo}] 信息被删除'

        # 先整理ip顺序
        # sorted_ipdb = { k:ipdb[k] for k in sorted(ipdb.keys()) }
        sorted_ipdb = {k:v for k,v in sorted(ipdb.items(), key=lambda item: IPy.IP(item[0]).int())}
        # 重写ipdb数据库
        with open('/usr/share/nginx/html/trserver/ipdb.json', "w", encoding="utf-8") as f:
            f.write(json.dumps(sorted_ipdb))

    return result


# IPV6的相关接口API
@app.get("/trserver/getnamebyipv6/{ip}")
async def getnamebyipv6(ip):
    # 准备待查的数据库
    with open("/usr/share/nginx/html/trserver/ipv6db.json", "r", encoding="utf-8") as f:
        ipdb=json.load(f)

    _ip = IPy.IP(ip)

    result = {}
    for dstip, dstinfo in ipdb.items():
        dstip = IPy.IP(dstip)
        if _ip in dstip:
            result[dstinfo] = dstip.prefixlen()

    if len(result):
        resultinfo, _ = max(result.items(), key = lambda x: x[1])
        # return(resultinfo)
        return RetItem(dbinfo='ipdb', ipinfo=resultinfo)
    else:
        # 这里要去纯真数据库里查询
        # return("???")
        database_path = "/usr/share/nginx/html/trserver/czdb/cz88_public_v6.czdb"
        query_type = "BTREE"
        key = "uK+eMTs27M0Td8b3SkUNpw=="
        # ip = "2001:1::1"

        db_searcher = DbSearcher(database_path, query_type, key)

        try:
            region = db_searcher.search(ip)
            # print("搜索结果：")
            # print(region)
            region = region.replace('\t', ' ☆ ')
            # return region
            return RetItem(dbinfo='czdb', ipinfo=region)
        except Exception as e:
            # print(f"An error occurred during the search: {e}")
            return f"An error occurred during the search: {e}"
        finally:
            db_searcher.close()

# 返回指定ipv6的信息
@app.get("/trserver/getipv6db/")
async def getipv6db(ip=None):
    # 准备待查的数据库
    with open("/usr/share/nginx/html/trserver/ipv6db.json", "r", encoding="utf-8") as f:
        ipdb=json.load(f)

    if not ip:
        # 无查询的ip，返回全部数据
        return ipdb
    else:
        # 返回匹配指定ip的路由
        _ip = IPy.IP(ip)

        # 保存所有匹配的路由
        result = {
            "db":"",
            "ipinfo":[]
        }
        _result = []
        for dstip, dstinfo in ipdb.items():
            dstip = IPy.IP(dstip)
            if _ip in dstip:
                _result.append((dstip.prefixlen(), dstip.strNormal(), dstinfo))

        # 按最长匹配原则，从大到小排列后，返回数据
        ret = sorted([(deviceip, devicename) for (prefix, deviceip, devicename) in _result], key=lambda prefix:prefix, reverse=True)

        # 如果所查询的ip在ipdb中
        if len(ret):
            result["db"] = "ipdb"
            result["ipinfo"] = ret
            return result
        else:
            # 所查询的ip不在ipdb中，在czdb中查询
            database_path = "/usr/share/nginx/html/trserver/czdb/cz88_public_v6.czdb"
            query_type = "BTREE"
            key = "uK+eMTs27M0Td8b3SkUNpw=="

            db_searcher = DbSearcher(database_path, query_type, key)

            try:
                region = db_searcher.search(ip)
                # print("搜索结果：")
                # print(region)
                region = region.replace('\t', ' ☆ ')
                result["db"] = "czdb"
                result["ipinfo"].append((ip, region))
                return result
            except Exception as e:
                # print(f"An error occurred during the search: {e}")
                return f"An error occurred during the search: {e}"
            finally:
                db_searcher.close()

@app.post("/trserver/updatenamebyipv6/")
async def updatenamebyipv6(item: Item):
    # print(item)
    data={item.deviceip:item.devicename}
    # 准备待查的数据库
    with open("/usr/share/nginx/html/trserver/ipv6db.json", "r", encoding="utf-8") as f:
        ipdb=json.load(f)

    # 更新数据库
    ipdb.update(data)

    # 先整理ip顺序
    # sorted_ipdb = { k:ipdb[k] for k in sorted(ipdb.keys()) }
    sorted_ipdb = {k:v for k,v in sorted(ipdb.items(), key=lambda item: IPy.IP(item[0]).int())}
    # 重写数据库文件    
    with open('/usr/share/nginx/html/trserver/ipv6db.json', "w", encoding="utf-8") as f:
        f.write(json.dumps(sorted_ipdb))
  
    return item

@app.post("/trserver/deletenamebyipv6/")
async def deletenamebyipv6(ip_network:IP_NETWORK):
    ip = ip_network.deviceip
    result = {"deviceip":ip, "devicename":"没有对应的信息"}

    # 准备待查的数据库
    with open("/usr/share/nginx/html/trserver/ipv6db.json", "r", encoding="utf-8") as f:
        ipdb=json.load(f)

    # ipdb中是否有指定的ip标记
    ret = ipdb.get(ip)
    if ret:
        deletedinfo = ipdb.pop(ip)
        result["devicename"] = f'对应的 [{deletedinfo}] 信息被删除'

        # 先整理ip顺序
        # sorted_ipdb = { k:ipdb[k] for k in sorted(ipdb.keys()) }
        sorted_ipdb = {k:v for k,v in sorted(ipdb.items(), key=lambda item: IPy.IP(item[0]).int())}
        # 重写ipdb数据库
        with open('/usr/share/nginx/html/trserver/ipv6db.json', "w", encoding="utf-8") as f:
            f.write(json.dumps(sorted_ipdb))

    return result


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=9090)