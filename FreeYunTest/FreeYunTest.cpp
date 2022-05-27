// FreeYunTest.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <ACEBase.h>
#include <ACEConnect.h>
#include <iostream>
#include <HttpClient.h>
#include <FreeYun.h>
#pragma comment(lib,"FreeYun.lib")
#include<bitset>
int main()
{
    HttpClient client;

  std::string r;
  auto Code =  client.Get("http://www.freeyun.net/auther/index.html",r);



    auto util = std::make_unique<CACEUtil>();



   //ACEInfoLog("{0}", util->UTF8_To_string(r).c_str());

   //ACEInfoLog("{0} {1}", Code, client.GetErrorStr(Code).c_str());

   //ACEWarningLog("{0}", client.GetHttpHeader().c_str());
    FreeYun yun;

    auto info = yun.CloudInit(&TAG_ANTI_FREEYUN_INIT_INFO("1168", "27A5172AFA54D2F4A202EA76B4B43612", "COxlsBLt", "KzEWarV4N8", "9303", "122", 0));

    if (std::get<0>(info))
    {
		ACEInfoLog("{}", util->UTF8_To_string(std::get<2>(info).dump()));



		info = yun.CloudLogin("121231", "33", "md5");

        if (std::get<0>(info))
        {
            ACEInfoLog("{}", util->UTF8_To_string(std::get<2>(info).dump()));
        }
        else
        {
            ACEInfoLog("{} errorCode:{}  {}", std::get<0>(info), yun.GetErrorCode(), util->UTF8_To_string(std::get<1>(info)));
        }
       info = yun.CloudPay("121231", "01A90480F419FA6AC474AD03D837E5AB");

		if (std::get<0>(info))
		{
            ACEInfoLog("{}", util->UTF8_To_string(std::get<2>(info).dump()));
		}
        else
        {
            ACEInfoLog("{} errorCode:{}  {}", std::get<0>(info), yun.GetErrorCode(), util->UTF8_To_string(std::get<1>(info)));
        }

		info = yun.CloudQueryUserInfo("121231");

		if (std::get<0>(info))
		{
			ACEInfoLog("{}", util->UTF8_To_string(std::get<2>(info).dump()));		
		}
		else
		{
			ACEInfoLog("{} errorCode:{}  {}", std::get<0>(info), yun.GetErrorCode(), util->UTF8_To_string(std::get<1>(info)));
		}


  //      info = yun.CloudBlackLst("121231");

		//if (std::get<0>(info))
		//{
		//	ACEInfoLog("{}", util->UTF8_To_string(std::get<2>(info).dump()));
		//}
		//else
		//{
		//	ACEInfoLog("{} errorCode:{}  {}", std::get<0>(info), yun.GetErrorCode(), util->UTF8_To_string(std::get<1>(info)));
		//}
		info = yun.CloudChangePassword("121231","33","33");

		if (std::get<0>(info))
		{
			ACEInfoLog("{}", util->UTF8_To_string(std::get<2>(info).dump()));
		}
		else
		{
			ACEInfoLog("{} errorCode:{}  {}", std::get<0>(info), yun.GetErrorCode(), util->UTF8_To_string(std::get<1>(info)));
		}

		//info = yun.CloudExit("121231");

		//if (std::get<0>(info))
		//{
		//	ACEInfoLog("{}", util->UTF8_To_string(std::get<2>(info).dump()));
		//}
		//else
		//{
		//	ACEInfoLog("{} errorCode:{}  {}", std::get<0>(info), yun.GetErrorCode(), util->UTF8_To_string(std::get<1>(info)));
		//}
		
		info = yun.CloudGetVersionInfo();

		if (std::get<0>(info))
		{
			ACEInfoLog("{}", util->UTF8_To_string(std::get<2>(info).dump()));
		}
		else
		{
			ACEInfoLog("{} errorCode:{}  {}", std::get<0>(info), yun.GetErrorCode(), util->UTF8_To_string(std::get<1>(info)));
		}
		
		info = yun.CloudGetPayCardList();

		if (std::get<0>(info))
		{
			ACEInfoLog("{}", util->UTF8_To_string(std::get<2>(info).dump()));
		}
		else
		{
			ACEInfoLog("{} errorCode:{}  {}", std::get<0>(info), yun.GetErrorCode(), util->UTF8_To_string(std::get<1>(info)));
		}

		info = yun.CloudGetUserStatus("121231");

		if (std::get<0>(info))
		{
			ACEInfoLog("{}", util->UTF8_To_string(std::get<2>(info).dump()));
		}
		else
		{
			ACEInfoLog("{} errorCode:{}  {}", std::get<0>(info), yun.GetErrorCode(), util->UTF8_To_string(std::get<1>(info)));
		}

		info = yun.CloudUserSubPoint("121231",100);

		if (std::get<0>(info))
		{
			ACEInfoLog("{}", util->UTF8_To_string(std::get<2>(info).dump()));
		}
		else
		{
			ACEInfoLog("{} errorCode:{}  {}", std::get<0>(info), yun.GetErrorCode(), util->UTF8_To_string(std::get<1>(info)));
		}


		info = yun.CloudCardLogin("0114F37E0AFA5CE9E2F9A48A8BE5682E", "md5");

		if (std::get<0>(info))
		{
			ACEInfoLog("{}", util->UTF8_To_string(std::get<2>(info).dump()));
		}
		else
		{
			ACEInfoLog("{} errorCode:{}  {}", std::get<0>(info), yun.GetErrorCode(), util->UTF8_To_string(std::get<1>(info)));
		}

		info = yun.CloudExecTelnetCode("0114F37E0AFA5CE9E2F9A48A8BE5682E", "test","myFunction","1=15,1=10");

		if (std::get<0>(info))
		{
			ACEInfoLog("{}", util->UTF8_To_string(std::get<2>(info).dump()));
		}
		else
		{
			ACEInfoLog("{} errorCode:{}  {}", std::get<0>(info), yun.GetErrorCode(), util->UTF8_To_string(std::get<1>(info)));
		}

		info = yun.CloudGetTeletVar("0114F37E0AFA5CE9E2F9A48A8BE5682E", "Cstrike_Check_1");

		if (std::get<0>(info))
		{
			ACEInfoLog("{}", util->UTF8_To_string(std::get<2>(info).dump()));
		}
		else
		{
			ACEInfoLog("{} errorCode:{}  {}", std::get<0>(info), yun.GetErrorCode(), util->UTF8_To_string(std::get<1>(info)));
		}
		info = yun.CloudHeartBeat("0114F37E0AFA5CE9E2F9A48A8BE5682E");

		if (std::get<0>(info))
		{
			ACEInfoLog("{}", util->UTF8_To_string(std::get<2>(info).dump()));
		}
		else
		{
			ACEInfoLog("{} errorCode:{}  {}", std::get<0>(info), yun.GetErrorCode(), util->UTF8_To_string(std::get<1>(info)));
		}

		info = yun.CloudChangeMachine("0114F37E0AFA5CE9E2F9A48A8BE5682E");

		if (std::get<0>(info))
		{
			ACEInfoLog("{}", util->UTF8_To_string(std::get<2>(info).dump()));
		}
		else
		{
			ACEInfoLog("{} errorCode:{}  {}", std::get<0>(info), yun.GetErrorCode(), util->UTF8_To_string(std::get<1>(info)));
		}
		/*info = yun.CloudFeedback(u8"留言反馈","2222@qq.com");

		if (std::get<0>(info))
		{
			ACEInfoLog("{}", util->UTF8_To_string(std::get<2>(info).dump()));
		}
		else
		{
			ACEInfoLog("{} errorCode:{}  {}", std::get<0>(info), yun.GetErrorCode(), util->UTF8_To_string(std::get<1>(info)));
		}*/
		
		//info = yun.CloudUpLoadClientExceptionInfo(u8"异常标签",u8"一场内容", u8"win7");

		//if (std::get<0>(info))
		//{
		//	ACEInfoLog("{}", util->UTF8_To_string(std::get<2>(info).dump()));
		//}
		//else
		//{
		//	ACEInfoLog("{} errorCode:{}  {}", std::get<0>(info), yun.GetErrorCode(), util->UTF8_To_string(std::get<1>(info)));
		//}

		info = yun.CloudGetUserPermission(u8"0114F37E0AFA5CE9E2F9A48A8BE5682E");

		if (std::get<0>(info))
		{
			ACEInfoLog("{}", util->UTF8_To_string(std::get<2>(info).dump()));
		}
		else
		{
			ACEInfoLog("{} errorCode:{}  {}", std::get<0>(info), yun.GetErrorCode(), util->UTF8_To_string(std::get<1>(info)));
		}
		
		info = yun.CloudUsersOnlineCount();

		if (std::get<0>(info))
		{
			ACEInfoLog("{}", util->UTF8_To_string(std::get<2>(info).dump()));
		}
		else
		{
			ACEInfoLog("{} errorCode:{}  {}", std::get<0>(info), yun.GetErrorCode(), util->UTF8_To_string(std::get<1>(info)));
		}

		info = yun.CloudUserUnBind("0114F37E0AFA5CE9E2F9A48A8BE5682E");

		if (std::get<0>(info))
		{
			ACEInfoLog("{}", util->UTF8_To_string(std::get<2>(info).dump()));
		}
		else
		{
			ACEInfoLog("{} errorCode:{}  {}", std::get<0>(info), yun.GetErrorCode(), util->UTF8_To_string(std::get<1>(info)));
		}

		
        getchar();
    }
    ACEInfoLog("{} errorCode:{}  {}", std::get<0>(info), yun.GetErrorCode(), util->UTF8_To_string(std::get<1>(info)));
   

 


    //ciphertext
    //BYTE Code = 0x22;

    //std::bitset<32> a(0xFFFFFFFF);

   int Number = 0x4B;

   int k = (Number )  << 28;

   int c = Number & (1 << 4 - 1);

	//UCHAR sKey = (UCHAR)uKey;
	//ULONG uKey = (sKey << 24) | (sKey << 16) | (sKey << 8) | sKey;
	//PVOID lpAddress = (LPVOID)((ULONG)Address ^ uKey);



   /*
   *    0xFF << 24 = FF000000;
   *    0xFF << 16 = 00FF0000;
   *    0xFF << 8  = 0000FF00;
   *    FF000000|00FF0000|0000FF00|FF
   *    按位或->只有全0的时候才是0，其他情况都是1.

   *  
   */
	//UCHAR sKey = (UCHAR)0xFF;
	//ULONG uKey = (sKey << 24) | (sKey << 16) | (sKey << 16);


 //   int b = (0xFF & (1 << 5 - 1));

 //   int n = 0xAA | 0xCC;
    //10101010
    //11001100
    //11101110


    //printf("%d",a.to_ullong());
   ;

   getchar();

}
