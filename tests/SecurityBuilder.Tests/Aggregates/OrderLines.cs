using System;
using System.Collections.Generic;
using System.Text;

namespace SecurityBuilder.Tests.Aggregates;


public sealed record OrderLines(int ItemId, Guid OrderId, decimal price, int qte, decimal totalPrice);