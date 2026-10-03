"""
Order Management Service
"""

class OrderService:
    def __init__(self, db, notification_service):
        self.db = db
        self.notification_service = notification_service

    def create_order(self, customer_id, items, total_amount):
        order = {
            "customer_id": customer_id,
            "items": items,
            "total_amount": total_amount,
            "status": "PENDING"
        }
        self.db.orders.insert(order)
        return order

    def cancel_order(self, order_id, reason):
        order = self.db.orders.find_one({"_id": order_id})
        if not order:
            raise ValueError("Order not found")
        
        # MISSING CONTROL: Does not check shipment status (e.g. order["status"] == "SHIPPED")
        # MISSING CONTROL: Does not check total_amount threshold ($500) for approval
        order["status"] = "CANCELLED"
        order["cancel_reason"] = reason
        self.db.orders.update({"_id": order_id}, order)
        return order

    def ship_order(self, order_id, tracking_number):
        order = self.db.orders.find_one({"_id": order_id})
        order["status"] = "SHIPPED"
        order["tracking_number"] = tracking_number
        self.db.orders.update({"_id": order_id}, order)
        return order
