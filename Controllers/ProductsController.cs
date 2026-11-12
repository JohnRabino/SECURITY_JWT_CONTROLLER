using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SECURITY_JWT_CONTROLLER.Models;

namespace SECURITY_JWT_CONTROLLER.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ProductsController : ControllerBase
{
    private static readonly List<Product> _products = new()
    {
        new Product { Id = 1,  Name = "Mechanical Keyboard", Price = 3200m },
        new Product { Id = 2,  Name = "Gaming Mouse",         Price = 1850m },
        new Product { Id = 3,  Name = "27-inch 144Hz Monitor",Price = 12500m },
        new Product { Id = 4,  Name = "Gaming Headset",       Price = 2400m },
        new Product { Id = 5,  Name = "Mouse Pad (XL)",       Price = 650m },
        new Product { Id = 6,  Name = "RGB Mechanical Switch Pack", Price = 1200m },
        new Product { Id = 7,  Name = "Gaming Chair",         Price = 8900m },
        new Product { Id = 8,  Name = "Webcam 1080p",         Price = 2100m },
        new Product { Id = 9,  Name = "Controller (Wireless)",Price = 2800m },
        new Product { Id = 10, Name = "Capture Card",         Price = 5600m }
    };
    private static int _nextId = 11;

    private int GetNextId()
    {
        for (int i = 1; i < _nextId; i++)
        {
            if (!_products.Any(p => p.Id == i))
                return i;
        }
        return _nextId++;
    }

    [HttpGet]
    public IActionResult GetAll() => Ok(_products);

    [HttpGet("{id}")]
    public IActionResult GetById(int id)
    {
        var p = _products.FirstOrDefault(x => x.Id == id);
        return p is null ? NotFound() : Ok(p);
    }

    [Authorize(Roles = "Admin")]
    [HttpPost]
    public IActionResult Create(Product input)
    {
        input.Id = GetNextId();
        _products.Add(input);
        return CreatedAtAction(nameof(GetById), new { id = input.Id }, input);
    }

    [Authorize(Roles = "Admin")]
    [HttpPut("{id}")]
    public IActionResult Update(int id, Product input)
    {
        var p = _products.FirstOrDefault(x => x.Id == id);
        if (p is null) return NotFound();
        p.Name = input.Name;
        p.Price = input.Price;
        return Ok(p);
    }

    [Authorize(Roles = "Admin")]
    [HttpDelete("{id}")]
    public IActionResult Delete(int id)
    {
        var p = _products.FirstOrDefault(x => x.Id == id);
        if (p is null) return NotFound();
        _products.Remove(p);
        return NoContent();
    }
}