export function newFileSource(title:string):string{
    return `rule "${title}"
when
    has_field("transaction_date")
then
// the following date format assumes there's no time zone in the string
    let new_date = parse_date(to_string($message.transaction_date), "yyyy-MM-dd HH:mm:ss");
    set_field("transaction_year", new_date.year)  ; 
end`;
}

