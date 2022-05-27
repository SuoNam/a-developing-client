#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/client.hpp>
#include <websocketpp/common/thread.hpp>
#include <websocketpp/common/memory.hpp>
#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <sstream>
#include<cstdlib>
#include<cstdio>
#include"json.h"
#include"sha256.h"
#include<iomanip>
#include"requests.h"
#include"base64.h"
#include<fstream>
#include <mutex>
#include <condition_variable>
#include <thread>
#include"base.h"
#define BUFFER_SIZE                1024
using std::cout;
using namespace::std;
using std::cout;
using std::cin;
using std::string;
using std::endl;
std::mutex mut;
std::condition_variable data_cond;
typedef websocketpp::client<websocketpp::config::asio_client> client;
void notify() {
	 
		std::lock_guard<std::mutex> lk(mut);
		data_cond.notify_all();
}
void wait(int*verify) {
	std::unique_lock<std::mutex> lk(mut);
	data_cond.wait(lk, [&] {return ( *verify==1 || *verify==2); });
	lk.unlock();
}



class connection_metadata {
public:
	typedef websocketpp::lib::shared_ptr<connection_metadata> ptr;


	connection_metadata(int id, websocketpp::connection_hdl hdl, std::string uri)
		: m_id(id)
		, m_hdl(hdl)
		, m_status("Connecting")
		, m_uri(uri)
		, m_server("N/A")
	{}

	void on_open(client* c, websocketpp::connection_hdl hdl) {
		m_status = "Open";

		client::connection_ptr con = c->get_con_from_hdl(hdl);
		m_server = con->get_response_header("Server");
	}

	void on_fail(client* c, websocketpp::connection_hdl hdl) {
		m_status = "Failed";

		client::connection_ptr con = c->get_con_from_hdl(hdl);
		m_server = con->get_response_header("Server");
		m_error_reason = con->get_ec().message();
	}

	void on_close(client* c, websocketpp::connection_hdl hdl) {
		m_status = "Closed";
		client::connection_ptr con = c->get_con_from_hdl(hdl);
		std::stringstream s;
		s << "close code: " << con->get_remote_close_code() << " ("
			<< websocketpp::close::status::get_string(con->get_remote_close_code())
			<< "), close reason: " << con->get_remote_close_reason();
		m_error_reason = s.str();
	}

	void on_message(websocketpp::connection_hdl, client::message_ptr msg) {
		if (msg->get_opcode() == websocketpp::frame::opcode::text) {
			m_messages.push_back("<< " + msg->get_payload());
			compare1(msg->get_payload());
			
		}
		else {
			m_messages.push_back("<< " + websocketpp::utility::to_hex(msg->get_payload()));
			
		}
	}
	void compare1(const string msg) {
	
 if (msg == "1") {
			cout << "\n" << "失败" << endl;
			Sleep(1000);
			verify = 2;

		}
		else {
	        
			cout << "\n" << "登入成功" << endl;
			Sleep(1000);
			notify();
			verify = 1;

		}
 /*
		const string rt = exchange(msg);
		if (rt == "Signin") {
			const string status = back(msg);
			if (status == "Success") {
				cout << "欢迎登入" << endl;
				notify();
				verify = 1;
			}
			else {
				cout << "登入失败" << endl;
				notify();
				verify = 2;
			}
		}

	     else if (rt == "Message") {
			cout << msg << endl;
		}
		 else if (rt == "File") {
			string backmessage = filenameReturntojson(msg);
			if (backmessage == "Success") {
				notify();
				fileverify = 1;
			}
			else if (backmessage == "Error") {
				notify();
				error = filenameReturntojsonError(msg);
				fileverify = 2;
			}
		}*/
	}
	websocketpp::connection_hdl get_hdl() const {
		return m_hdl;
	}

	int get_id() const {
		return m_id;
	}

	std::string get_status() const {
		return m_status;
	}

	void record_sent_message(std::string message) {
		m_messages.push_back(">> " + message);
	}
	

	friend std::ostream& operator<< (std::ostream& out, connection_metadata const& data);
	std::vector<std::string> m_messages;
	int verify=3;
	int fileverify = 0;
	string error;
private:
	int m_id;
	websocketpp::connection_hdl m_hdl;
	std::string m_status;
	std::string m_uri;
	std::string m_server;
	std::string m_error_reason;
	
	
};
std::ostream& operator<< (std::ostream& out, connection_metadata const& data) {
	std::vector<std::string>::const_iterator it;
	for (it = data.m_messages.begin(); it != data.m_messages.end(); ++it) {
		out << *it << "\n";
	}

	return out;
}
class websocket_endpoint {
public:
	websocket_endpoint() : m_next_id(0) {
		m_endpoint.clear_access_channels(websocketpp::log::alevel::all);
		m_endpoint.clear_error_channels(websocketpp::log::elevel::all);

		m_endpoint.init_asio();
		m_endpoint.start_perpetual();

		m_thread = websocketpp::lib::make_shared<websocketpp::lib::thread>(&client::run, &m_endpoint);
	}

	~websocket_endpoint() {
		m_endpoint.stop_perpetual();

		for (con_list::const_iterator it = m_connection_list.begin(); it != m_connection_list.end(); ++it) {
			if (it->second->get_status() != "Open") {

				continue;
			}

			std::cout << "> Closing connection " << it->second->get_id() << std::endl;

			websocketpp::lib::error_code ec;
			m_endpoint.close(it->second->get_hdl(), websocketpp::close::status::going_away, "", ec);
			if (ec) {
				std::cout << "> Error closing connection " << it->second->get_id() << ": "
					<< ec.message() << std::endl;
			}
		}

		m_thread->join();
	}

	int connect(std::string const& uri) {
		websocketpp::lib::error_code ec;

		client::connection_ptr con = m_endpoint.get_connection(uri, ec);

		if (ec) {
			std::cout << "> Connect initialization error: " << ec.message() << std::endl;
			return -1;
		}

		int new_id = m_next_id++;
		connection_metadata::ptr metadata_ptr = websocketpp::lib::make_shared<connection_metadata>(new_id, con->get_handle(), uri);
		m_connection_list[new_id] = metadata_ptr;

		con->set_open_handler(websocketpp::lib::bind(
			&connection_metadata::on_open,
			metadata_ptr,
			&m_endpoint,
			websocketpp::lib::placeholders::_1
		));
		con->set_fail_handler(websocketpp::lib::bind(
			&connection_metadata::on_fail,
			metadata_ptr,
			&m_endpoint,
			websocketpp::lib::placeholders::_1
		));
		con->set_close_handler(websocketpp::lib::bind(
			&connection_metadata::on_close,
			metadata_ptr,
			&m_endpoint,
			websocketpp::lib::placeholders::_1
		));
		con->set_message_handler(websocketpp::lib::bind(
			&connection_metadata::on_message,
			metadata_ptr,
			websocketpp::lib::placeholders::_1,
			websocketpp::lib::placeholders::_2
		));
		
		m_endpoint.connect(con);

		return new_id;
	}



	void close(int id, websocketpp::close::status::value code, std::string reason) {
		websocketpp::lib::error_code ec;

		con_list::iterator metadata_it = m_connection_list.find(id);
		if (metadata_it == m_connection_list.end()) {
			std::cout << "> No connection found with id " << id << std::endl;
			return;
		}

		m_endpoint.close(metadata_it->second->get_hdl(), code, reason, ec);
		if (ec) {
			std::cout << "> Error initiating close: " << ec.message() << std::endl;
		}
	}

	void send(int id, std::string message) {
		websocketpp::lib::error_code ec;

		con_list::iterator metadata_it = m_connection_list.find(id);
		if (metadata_it == m_connection_list.end()) {
			std::cout << "> No connection found with id " << id << std::endl;
			return;
		}

		m_endpoint.send(metadata_it->second->get_hdl(), message, websocketpp::frame::opcode::text, ec);
		if (ec) {
			std::cout << "发送错误原因： " << ec.message() << std::endl;
			return;
		}
		metadata_it->second->record_sent_message(message);
	}
	void sendFile(int id, const char*  message,signed long size) {
		websocketpp::lib::error_code ec;

		con_list::iterator metadata_it = m_connection_list.find(id);
		if (metadata_it == m_connection_list.end()) {
			std::cout << "> No connection found with id " << id << std::endl;
			return;
		}

		m_endpoint.send(metadata_it->second->get_hdl(), message,size,websocketpp::frame::opcode::binary,ec);
		if (ec) {
			std::cout << "发送错误原因： " << ec.message() << std::endl;
			return;
		}
		
	}

	connection_metadata::ptr get_metadata(int id) const {
		con_list::const_iterator metadata_it = m_connection_list.find(id);
		if (metadata_it == m_connection_list.end()) {
			return connection_metadata::ptr();
		}
		else {
			return metadata_it->second;
		}
	}
	connection_metadata::ptr  metadata_ptr;
	client m_endpoint;
private:
	typedef std::map<int, connection_metadata::ptr> con_list;

	
	websocketpp::lib::shared_ptr<websocketpp::lib::thread> m_thread;
	
	con_list m_connection_list;
	int m_next_id;
};
string compare(signed int size) {
	if (size >= 1024) {
		string attach = "Need compress";
		return attach;
	}
	else
	{
		string attach = "Don't need compress";
		return attach;
	}
}




int main() {
	bool done = false;
	std::string input;
	websocket_endpoint endpoint;
	std::string 账号;
	std::string 密码;
	string 类型;
	std::string 连接网址 = "ws://121.40.165.18:8800";
	std::cout << "请输入连接网址：";
	getline(cin, 连接网址);
	int id = endpoint.connect(连接网址);
	if (id != -1) {

		std::cout << "> 您的连接为第  " << id << "个" << std::endl;
	}
	connection_metadata::ptr m = endpoint.get_metadata(id);
	q:cout <<endl<< "你要执行什么（登入or注册）：";
	     string order = "0";
		 std::getline(std::cin,order);
		if (order == "登入") {
			int which = 0;
			string orderwhich = order + " " + to_string(which);
		r:std::stringstream ss(orderwhich);
			std::cout << endl << "输入账号:";
			std::getline(std::cin, 账号);
			std::cout << endl << "输入密码:";
			std::getline(std::cin, 密码);
			string g = 写入(密码, 账号);
			std::string cmd;
			int a;
			ss >> cmd >> a;
			endpoint.send(a, g);
			/*int* p = &(*m).verify;
			wait(p);
			if ((*m).verify == 2) {
				goto r;
			}
			(*m).verify=3;*/
		}
		else if (order == "注册") {
			string z = "123";
			cout << "Sorry!帅气的索先生还没有完成此功能，请敬请期待。" << endl;
			cout << "请您输入sjkzs结束程序or输入返回重新尝试其他内容" << endl;
			std::getline(cin, z);
			if (z == "sjkzs") {
				return 0;
			}
			else if (z == "返回") {
				goto q;
			}
			else {
				cout << "你不乖啊！";
				   std::unique_lock<std::mutex> lk(mut);
			}
		}
		/*auto resp2 = requests::post("http://starlink.vaiwan.com/api/query/userPublicInfo", "{ \"account\":\"ST\" }");
		if (resp2 == NULL) {
			printf("请求失败\n");
		}
		else {
			// printf("%d %s\r\n", resp2->status_code, resp2->status_message());
			 //printf("%s\n", resp2->body.c_str());
			string requestmessage = resp2->body.c_str();
			string status = resp2->status_message();
			cout << requestmessage << endl;
		}*/
		while (!done) {

		z:std::cout << "输入命令: ";
			std::getline(std::cin, input);


			if (input == "停止") {
				done = true;
			}
			else if (input.substr(0, 4) == "发送") {
				std::stringstream ss(input);

				std::string cmd;
				int id;
				std::string message;

				ss >> cmd >> id;
				std::getline(ss, message);
				string jsonmessage = changetoJsonpublic(message);
				endpoint.send(id, jsonmessage);
			}
			else if (input.substr(0, 4) == "上传") {
				auto id_addr1 = input.find_first_of(':');
				auto  id_addr2 = input.find_first_of(':', id_addr1 + 1);
				string file_name = input.substr(id_addr1 + 1, id_addr2 - id_addr1 - 1);
				signed long long size;
				ifstream in(file_name, ios::in | ios::binary);
				if (!in.good()) {
					cerr << "error:create file happen mistake";
					goto z;
				}
				in.seekg(0, ios::end);
				size = in.tellg();//获得文件大小
				string attach = compare(size);
				in.seekg(0, ios::beg);
				char* buffer = new char[size];//创建buffer
				in.read(buffer, size);//读文件in，（以二进制形式）
				in.close();
				string filecontentsha256 = sha256(buffer);//把文件内容sha256编码
				string size1 = to_string(size);
				string filejsonfirstsend = filenametojson(file_name, filecontentsha256, size1, attach);//写成New json格式
				long long length = filejsonfirstsend.size();//获取需base64的大小
				unsigned char* filejsonfirstsendchar = (unsigned char*)filejsonfirstsend.c_str();
				string filejsonfirstout = base64_encode(filejsonfirstsendchar, length);
				string among = "|";
				string filesendmessage = filejsonfirstout + among;
				int sz = filesendmessage.size();
				endpoint.sendFile(id, filesendmessage.c_str(), sz);
				/*int* pfile = &(*m).fileverify;
				wait(pfile);
				if ((*m).fileverify == 2) {
					cout << (*m).error << endl;
				}
				(*m).fileverify = 3;*/
				//传输文件append
				string appendfilejson = Appandjson(filecontentsha256);
				int lengthappend = appendfilejson.size();
				unsigned char* appendfilejsonunsignedchar;
				appendfilejsonunsignedchar = (unsigned char*)(appendfilejson.c_str());
				string appendfilejsonchar = base64_encode(appendfilejsonunsignedchar, lengthappend);
				char buffer1[BUFFER_SIZE];
				FILE* fp;
				errno_t err;
				fopen_s(&fp, file_name.c_str(), "rb");
				if (fp == NULL) {
					cout << file_name << "open error" << endl;
					return 0;
				}
				int file_block_length = 0;
				int t = 1;
				while (1)
				{
					memset(buffer1, 0, 1024);
					file_block_length = fread(buffer1, 1, BUFFER_SIZE, fp);
					if (file_block_length > 0) {
						string Sendmessagefileappend = appendfilejsonchar + among + buffer1;
						long size3 = Sendmessagefileappend.size();
						endpoint.sendFile(id, Sendmessagefileappend.c_str(), size3);
						cout << buffer1 << endl;
						cout << t << endl;
						t++;
						/*wait(pfile);
						if ((*m).fileverify == 2) {
							cout << (*m).error << endl;
						}
						(*m).fileverify = 3;*/
					}
					else {
						break;
					}
				}
				fclose(fp);
				/*string Sendmessagefileappend = appendfilejsonchar + among + buffer;
				long size3 = Sendmessagefileappend.size();
				endpoint.sendFile(id, Sendmessagefileappend.c_str(), size3);
				wait(pfile);
				if ((*m).fileverify == 2) {
					cout << (*m).error << endl;
				}
				(*m).fileverify = 3;*/
				//Complete
				string Completemessageuncomplete = competetjson(filecontentsha256);
				int sizecomplete = Completemessageuncomplete.size();
				const unsigned char* Completemessageuncompletechar = (const unsigned char*)Completemessageuncomplete.c_str();
				string Completemessage = base64_encode(Completemessageuncompletechar, sizecomplete) + among;
				int szo = Completemessage.size();
				endpoint.sendFile(id, Completemessage.c_str(), szo);
				/*wait(pfile);
				if ((*m).fileverify == 2) {
					cout << (*m).error << endl;
				}
				(*m).fileverify = 3;*/
			}
			else if (input.substr(0, 4) == "关闭") {
				std::stringstream ss(input);

				std::string cmd;
				int id;
				int close_code = websocketpp::close::status::normal;
				std::string reason;

				ss >> cmd >> id >> close_code;
				std::getline(ss, reason);

				endpoint.close(id, close_code, reason);
			}
			else if (input.substr(0, 4) == "显示") {
				int id = atoi(input.substr(5).c_str());

				connection_metadata::ptr metadata = endpoint.get_metadata(id);
				if (metadata) {
					std::cout << *metadata << std::endl;
				}
				else {
					std::cout << "> Unknown connection id " << id << std::endl;
				}
			}
			else {
				std::cout << "> Unrecognized Command" << std::endl;
			}

		}
	}

	