#include<json/json.h>
#include <string>
using std::string;



string д��(string Pwd, string Account, string P)
{
    string a;
    string type = "Signin";
    //���ڵ�
    Json::Value root;

    //���ڵ�����
    root["Type"] = Json::Value(type);

    //�ӽڵ�
    Json::Value Info;

    //�ӽڵ�����
    Info["Account"] = Json::Value(Account);
    Info["Pwd"] = Json::Value(Pwd);
    Info["P"] = Json::Value(P);


    //�ӽڵ�ҵ����ڵ���
    root["Info"] = Json::Value(Info);


    //ֱ�����
    Json::FastWriter fw;
    a = fw.write(root);
    return a;

    /*
    //json�ļ��������£�
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