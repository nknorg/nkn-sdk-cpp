#ifndef __NKN_SFINAE_H__
#define __NKN_SFINAE_H__

#include <type_traits>

template<typename... Ts>
struct has_member_helper {};

template<typename T, typename _ = void>
struct is_container : std::false_type {};

template<typename T>
struct is_container<
        T,
        typename std::conditional<
                    false,
                    has_member_helper<
                        typename T::value_type,
                        typename T::iterator,
                        typename T::const_iterator,
                        decltype(std::declval<T>().push_back()),
                        decltype(std::declval<T>().size()),
                        decltype(std::declval<T>().begin()),
                        decltype(std::declval<T>().end()),
                        decltype(std::declval<T>().cbegin()),
                        decltype(std::declval<T>().cend())
                        >,
                    void
                 >::type
        > : public std::true_type {};

template<typename T, typename _ = void>
struct is_contiguous_container : std::false_type {};

template<typename T>
struct is_contiguous_container<
        T,
        typename std::conditional<
                    false,
                    has_member_helper<
                        typename T::value_type,
                        typename T::iterator,
                        typename T::const_iterator,
                        decltype(std::declval<T>().capacity()),
                        decltype(std::declval<T>().push_back()),
                        decltype(std::declval<T>().data()),
                        decltype(std::declval<T>()[0]),
                        decltype(std::declval<T>().size()),
                        decltype(std::declval<T>().begin()),
                        decltype(std::declval<T>().end()),
                        decltype(std::declval<T>().cbegin()),
                        decltype(std::declval<T>().cend())
                        >,
                    void
                 >::type
        > : public std::true_type {};

template<typename T, typename _ = void>
struct is_uBigInt: std::false_type {};

template<typename U>
struct is_uBigInt<
            U,
            typename std::conditional<
                    false,
                    has_member_helper<
                        decltype(std::declval<U>().Value()),
                        decltype(std::declval<U>().toBytes()),
                        decltype(std::declval<U>().toHexString()),
                        decltype(std::declval<U>().FromHexString("")),
                        decltype(std::declval<U>().FromBytes((unsigned char*)nullptr))
                    >,
                    void
            >::type
> : public std::true_type {};

#endif //__NKN_SFINAE_H__
