#pragma once

#include <type_traits>
#include <cstdio>
#include <gtest/gtest.h>


/*
 * EXPECT_TRUE(Matches(buff, out_buff, size));
 */
template<typename T>
inline testing::AssertionResult Matches(T const* expected, void const* actual, std::size_t size)
{
	for (std::size_t i = 0; i < size; ++i)
	{
		if (expected[i] != static_cast<T const*>(actual)[i])
		{
			char sz[256];
			std::snprintf(sz, sizeof(sz), "mismatch at %zu[0x%zX]: expected=0x%X, actual=0x%X"
					, i, i, expected[i], static_cast<T const*>(actual)[i]);
			return testing::AssertionFailure() << sz;
		}
	}

	return ::testing::AssertionSuccess();
}

/*
 * EXPECT_TRUE(Matches(buff, out_buff));
 */
template <typename T, std::size_t size>
inline testing::AssertionResult Matches(T const(&expected)[size], T const* actual)
{
	return Matches(expected, actual, size);
}

/*
 * EXPECT_TRUE(Matches(exp, got));
 */
template <typename T, std::size_t size, class GOT>
inline auto Matches(T const(&expected)[size], GOT const& got) ->
	std::enable_if_t<
		std::is_pointer_v<decltype(got.data() + got.size())>
		, testing::AssertionResult
	>
{
	return (size != got.size())
		? testing::AssertionFailure() << "size mismatch: expected=" << size << ", actual=" << got.size()
		: Matches(expected, got.data(), size);
}

template <class EXP, class GOT>
inline auto Matches(EXP const& exp, GOT const& got) ->
	std::enable_if_t<
		std::is_pointer_v<decltype(exp.data() + exp.size())> &&
		std::is_pointer_v<decltype(got.data() + got.size())>
		, testing::AssertionResult
	>
{
	return (exp.size() != got.size())
		? testing::AssertionFailure() << "size mismatch: expected=" << exp.size() << ", actual=" << got.size()
		: Matches(exp.data(), got.data(), exp.size());
}

