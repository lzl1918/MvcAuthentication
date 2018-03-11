using System;
using System.Collections.Generic;
using System.Text;

namespace AuthenticationCore.Internals.Helpers
{
    internal static class GroupHelper
    {
        internal static Dictionary<TKey, List<TValue>> GroupBy<TKey, TValue>(TValue[] elements, Func<TValue, TKey> evaluator)
        {
            Dictionary<TKey, List<TValue>> dic = new Dictionary<TKey, List<TValue>>();
            TKey key;
            List<TValue> lst;
            foreach (TValue element in elements)
            {
                key = evaluator(element);
                if (!dic.TryGetValue(key, out lst))
                {
                    lst = new List<TValue>();
                    dic[key] = lst;
                }
                lst.Add(element);
            }
            return dic;
        }
    }
}
