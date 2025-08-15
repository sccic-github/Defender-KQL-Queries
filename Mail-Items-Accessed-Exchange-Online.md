// Purpose: 
//     - Determine what emails were accessed in Exchange Online
//     - This is useful during account compromise to see if they accessed any emails. Could identify access of sensitive information
CloudAppEvents
| where Application contains "Exchange Online"
    // Insert the User Display Name you wish to investigate
    and AccountDisplayName contains "<Last Name>"
    // Insert the IP address you want to investigate
    and IPAddress == "<insert china IP>"
| where ActionType == "MailItemsAccessed"
| extend bind = tostring(parse_json(ActivityObjects[2]).Value)
| extend internetmsgid = tostring(parse_json(parse_json(parse_json(RawEventData).Folders[0]).FolderItems[0]).InternetMessageId)
| where bind == "Bind"
| project internetmsgid
