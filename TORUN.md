To build  

``` cargo build --release```  

To run  

``` ./target/release/node-blogchain --dev -lruntime=debug```

To swap between custom header and generic header, comment/uncomment lines 73/74 in ``` ./runtime/lib.rs```  

There a 1 or 2 fields in ```generic::Header``` that are implemented as methods in ```HookHeader``` so you'll have to change  
```header.number -> header.number()```  
```header.parent_hash -> header.parent_hash()```  
when you switch over

To start yarn, cd into 'substrate-front-end-template' and ```yarn start```  
Polkadot should be available on ```https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A9944#/explorer```