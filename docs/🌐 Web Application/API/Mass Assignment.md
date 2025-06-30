___
Certain application will assign values to keys and use them to create an object that encompasses those values. If you can discover controllable inputs (like adding an item to a cart, or checkout flow) you may be able to assign arbitrary values to params you're not supposed to - such as making `"discountPercent":100` etc... to discover potential assignable keys used to build objects. you can:

- Discover them in requests
- Code reveiw
- Fuzzing
- API leaking lots of data
- front end code
- JWT claims 

Once discovered, you can just make a request with the modified params.