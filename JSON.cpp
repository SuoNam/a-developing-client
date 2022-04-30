#include<json/json.h>
#include <string>
using std::string;



string 写入(string Pwd, string Account, string P)
{
    string a;
    string type = "Signin";
    //根节点
    Json::Value root;

    //根节点属性
    root["Type"] = Json::Value(type);

    //子节点
    Json::Value Info;

    //子节点属性
    Info["Account"] = Json::Value(Account);
    Info["Pwd"] = Json::Value(Pwd);
    Info["P"] = Json::Value(P);


    //子节点挂到根节点上
    root["Info"] = Json::Value(Info);


    //直接输出
    Json::FastWriter fw;
    a = fw.write(root);
    return a;

    /*
    //json文件内容如下：
    {
        "Type" : [""]

        "info" : {
            "account" : 1,
            "pwd" : "12234113",
            "p" : "web"
        }

    }
    */

}