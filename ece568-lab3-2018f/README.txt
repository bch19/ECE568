#Jason Qian, 1000624256, e-mail j.qian@mail.utoronto.ca
#Tzu-An Chen, 1000538411, e-mail bruce.chen@mail.utoronto.ca

Part 1 explanation:
We end the previous form and create a new form
Upon submitting our form, we create an img thats src contains the user's phished login


Part 2 explanation:


Part 3 explanation:
Exploitable field: Message
Payload: img is loaded from src, which causes the transfer


Part 4 explanation:
Exploitable field: Message
Payload: first iframe sets src of second iframe, which confirms the transfer


Part 5 explanation:
Exploitable field: Message
Payload: we load the page containing token inside iframe first, and use onload to extract the value of the token and append to our uri


Part 8 explanation:
PIN: 8546
We get the pin by subbing in values for N until we find a K and a K-1, where K causes the query to return that the account is valid and K-1 causes the query to return that the account is invalid. We can binary search to make finding K more efficient. Since the max pin is 9999, our initial value for N can be 10000 (to ensure the cc_number is in the table), or 5000

