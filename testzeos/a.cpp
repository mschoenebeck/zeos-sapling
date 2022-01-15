#include <stdio.h>
#include <stdint.h>
#include <vector>
#include <tuple>
#include <string>
#include <iostream>
#include <cmath>
#include "../../contract/json_struct/include/json_struct.h"

using namespace std;

namespace JS {
template <typename T>
struct TypeHandler<std::tuple<T, T, T>>
{
public:
  static inline Error to(std::tuple<T, T, T> &to_type, ParseContext &context)
  {
    if (context.token.value_type != JS::Type::ArrayStart)
      return Error::ExpectedArrayStart;
    Error error = context.nextToken();
    if (error != JS::Error::NoError)
      return error;
    
    to_type = std::tuple<T, T, T>{T(), T(), T()};
    error = TypeHandler<T>::to(get<0>(to_type), context);
    if (error != JS::Error::NoError)
    return error;
    error = context.nextToken();
    if (error != JS::Error::NoError)
    return error;

    error = TypeHandler<T>::to(get<1>(to_type), context);
    if (error != JS::Error::NoError)
    return error;
    error = context.nextToken();
    if (error != JS::Error::NoError)
    return error;

    error = TypeHandler<T>::to(get<2>(to_type), context);
    if (error != JS::Error::NoError)
    return error;
    error = context.nextToken();
    if (error != JS::Error::NoError)
    return error;

    if (context.token.value_type != JS::Type::ArrayEnd)
      return Error::ExpectedArrayEnd;
    
    return Error::NoError;
  }

  static inline void from(const std::tuple<T, T, T> &tup, Token &token, Serializer &serializer)
  {
    token.value_type = Type::ArrayStart;
    token.value = DataRef("[");
    serializer.write(token);

    token.name = DataRef("");

    T a, b, c;
    tie(a, b, c) = tup;
    TypeHandler<T>::from(a, token, serializer);
    TypeHandler<T>::from(b, token, serializer);
    TypeHandler<T>::from(c, token, serializer);

    token.name = DataRef("");

    token.value_type = Type::ArrayEnd;
    token.value = DataRef("]");
    serializer.write(token);
  }
};
}

typedef struct test
{
    uint64_t i;
    string s;
    JS_OBJ(i, s);
} test;

int main()
{
    unsigned long sum = 0;
    for(int i=0; i<=32; i++)
    {
        sum += pow(2, i);
    }
    
    std::cout << sum << std::endl;
    
/*
    tuple<test, test, test> t{{1, "miau"}, {2, "pferd"}, {3, "wurst"}};
    get<0>(t).s += "wau";

    std::vector<tuple<test, test, test>> v;

    v.push_back(t);
    v.push_back(t);

    std::string compact_json = JS::serializeStruct(v, JS::SerializerOptions(JS::SerializerOptions::Compact));
    
    cout << compact_json << endl;

    JS::ParseContext parseContext(compact_json);
    parseContext.parseTo(v);
    
    cout << get<0>(v[0]).s << endl;
*/
/*
    const uint64_t BLS_X = 0xd201'0000'0001'0000;
    for(int b=63; b>=0; b--)
    {
        bool i = (((BLS_X >>1) >> b) & 1) == 1;
        printf(i?"1":"0");
    }
    printf("\n");
    int b;
    bool i;
    for(b=63, i = ((((BLS_X >> 1) >> b) & 1) == 1); b>=0; --b, i = ((((BLS_X >> 1) >> b) & 1) == 1))
        printf(i?"1":"0");
*/
/*
    vector<uint64_t> data;
    data = {0, 1, 2, 3, 4, 5};
    printf("%lu\n", data[4]);
*/
/*
    uint8_t by[] = {255, 0, 15, 1};
    for(int i = 3; i >= 0; i--)
    {
        for(int j = i==3?6:7; j >= 0; j--)
        {
            printf( ((by[i] >> j) & 1) == 1 ? "1" : "0");
        }
    }
*/
/*
    const uint64_t BLS_X = 0xd201'0000'0001'0000;
    int b;
    bool i;
    for(b=63, i = ((((BLS_X >> 1) >> b) & 1) == 1); b>=0; --b, i = ((((BLS_X >> 1) >> b) & 1) == 1))
    {printf(i ? "true\n" : "false\n");}
*/
/*
    unsigned char a = 20;
    unsigned char b = 120;
    unsigned char c = a * b;
    
    printf("res = %u\n", c);
*/
}
