import axios from "axios";


const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;

const GROUP_CHAT_ID = process.env.TELEGRAM_GROUP_CHAT_ID;

const PERSONAL_CHAT_ID = process.env.TELEGRAM_PERSONAL_CHAT_ID;



export async function sendTelegramAlert(
    message:string,
    target:"group"|"personal"="group"
){

    const chatId =
        target === "group"
        ? GROUP_CHAT_ID
        : PERSONAL_CHAT_ID;


    if(!BOT_TOKEN || !chatId){

        console.log(
          "Telegram configuration missing"
        );

        return;
    }


    try{

        await axios.post(

        `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`,

        {
            chat_id: chatId,
            text: message,
            parse_mode:"HTML"
        }

        );


        console.log(
          "Telegram alert sent"
        );


    }
    catch(error){

        console.log(
          "Telegram Error",
          error
        );

    }

}
