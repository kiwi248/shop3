package com.shop3.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class CartOrderDto {
    private Long cartItemId;

    private List<CartOrderDto> cartOrderDtoList;
}
