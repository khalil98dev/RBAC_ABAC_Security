using Microsoft.EntityFrameworkCore;

namespace SecurityBuilder.Sample.Api.Endpoints;

/// <summary>
/// The hidden fields are nullable: a field the caller may not read comes back null (R5), and a
/// non-nullable property here would be refused instead (R12).
/// </summary>
public sealed record OrderDto(Guid Id, DateTime IssueDate, decimal? TotalAmmount, Guid? CustomerId);

public sealed record ProductDto(Guid Id, string Name, decimal? Price);

/// <summary>Only the fields sent are changed, so each one is checked for Set on its own (R6).</summary>
public sealed record UpdateOrderRequest(decimal? TotalAmmount, DateTime? IssueDate);

/// <summary>
/// Plain EF Core, nothing about permissions: the interceptors apply them. These endpoints carry no
/// RequireAuthorization either - an anonymous caller is denied by SecurityBuilder itself (R1).
/// </summary>
internal static class OrderEndpoints
{
    public static IEndpointRouteBuilder MapOrderEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/orders", async (SampleDbContext db, CancellationToken ct) =>
            await db.Orders
                .OrderBy(order => order.IssueDate)
                .Select(order => new OrderDto(order.Id, order.IssueDate, order.TotalAmmount, order.CustomerId))
                .ToListAsync(ct));

        app.MapGet("/orders/{id:guid}", async (Guid id, SampleDbContext db, CancellationToken ct) =>
            await db.Orders
                .Where(order => order.Id == id)
                .Select(order => new OrderDto(order.Id, order.IssueDate, order.TotalAmmount, order.CustomerId))
                .SingleOrDefaultAsync(ct) is { } order
                ? Results.Ok(order)
                : Results.NotFound());

        app.MapPut("/orders/{id:guid}", async (Guid id, UpdateOrderRequest request, SampleDbContext db, CancellationToken ct) =>
        {
            // Loading the order to change it needs Read (R9); saving it needs Set on each field sent.
            var order = await db.Orders.SingleOrDefaultAsync(order => order.Id == id, ct);

            if (order is null)
                return Results.NotFound();

            if (request.TotalAmmount is { } amount)
                order.TotalAmmount = amount;

            if (request.IssueDate is { } issueDate)
                order.IssueDate = issueDate;

            await db.SaveChangesAsync(ct);

            return Results.NoContent();
        });

        app.MapGet("/products", async (SampleDbContext db, CancellationToken ct) =>
            await db.Products
                .OrderBy(product => product.Name)
                .Select(product => new ProductDto(product.Id, product.Name, product.Price))
                .ToListAsync(ct));

        return app;
    }
}
